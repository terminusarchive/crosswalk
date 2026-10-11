use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
};

const WORKERS: usize = 2;

type Resolver = dyn Fn(IpAddr) -> Option<String> + Send + Sync + 'static;

struct RequestQueue {
    addresses: VecDeque<Request>,
    capacity: usize,
    stopped: bool,
}

struct SharedQueue {
    state: Mutex<RequestQueue>,
    ready: Condvar,
}

/// The queue, still usable when a thread panicked while holding it.
fn lock_queue(queue: &SharedQueue) -> MutexGuard<'_, RequestQueue> {
    queue
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

struct ResultMessage {
    address: IpAddr,
    generation: u64,
    name: Option<String>,
}

struct Request {
    address: IpAddr,
    generation: u64,
}

pub struct ReverseDns {
    enabled: bool,
    queue: Arc<SharedQueue>,
    pending: HashMap<IpAddr, u64>,
    pending_capacity: usize,
    results: Receiver<ResultMessage>,
    cache: HashMap<IpAddr, Option<String>>,
    cache_order: VecDeque<IpAddr>,
    cache_capacity: usize,
    generation: u64,
}

impl ReverseDns {
    pub fn new<F>(
        enabled: bool,
        request_capacity: usize,
        cache_capacity: usize,
        resolver: F,
    ) -> Self
    where
        F: Fn(IpAddr) -> Option<String> + Send + Sync + 'static,
    {
        let request_capacity = request_capacity.max(1);
        let cache_capacity = cache_capacity.max(1);
        let queue = Arc::new(SharedQueue {
            state: Mutex::new(RequestQueue {
                addresses: VecDeque::with_capacity(request_capacity),
                capacity: request_capacity,
                stopped: false,
            }),
            ready: Condvar::new(),
        });
        let (result_sender, results) = sync_channel(request_capacity.saturating_add(WORKERS));
        let resolver: Arc<Resolver> = Arc::new(resolver);
        for index in 0..WORKERS {
            let worker_queue = queue.clone();
            let worker_results = result_sender.clone();
            let worker_resolver = resolver.clone();
            let _ = thread::Builder::new()
                .name(format!("crosswalk-dns-{index}"))
                .spawn(move || resolver_worker(worker_queue, worker_results, worker_resolver));
        }
        drop(result_sender);
        Self {
            enabled,
            queue,
            pending: HashMap::new(),
            pending_capacity: request_capacity.saturating_add(WORKERS),
            results,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            cache_capacity,
            generation: 0,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.generation = self.generation.wrapping_add(1);
            self.cache.clear();
            self.cache_order.clear();
            self.pending.clear();
            let mut queue = lock_queue(&self.queue);
            queue.addresses.clear();
        }
    }

    pub fn schedule_visible(&mut self, addresses: impl IntoIterator<Item = IpAddr>) {
        if !self.enabled {
            return;
        }
        for address in addresses {
            if self.cache.contains_key(&address)
                || self.pending.contains_key(&address)
                || self.pending.len() >= self.pending_capacity
            {
                continue;
            }
            let mut queue = lock_queue(&self.queue);
            if queue.addresses.len() >= queue.capacity {
                continue;
            }
            queue.addresses.push_back(Request {
                address,
                generation: self.generation,
            });
            self.pending.insert(address, self.generation);
            self.queue.ready.notify_one();
        }
    }

    pub fn poll(&mut self) {
        while let Ok(result) = self.results.try_recv() {
            if self.pending.get(&result.address) == Some(&result.generation) {
                self.pending.remove(&result.address);
            }
            if self.enabled && result.generation == self.generation {
                self.cache_result(result.address, result.name);
            }
        }
    }

    pub fn name(&self, address: IpAddr) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        self.cache.get(&address).and_then(Option::as_deref)
    }

    pub fn display_name(&self, address: IpAddr) -> String {
        self.name(address)
            .map(str::to_owned)
            .unwrap_or_else(|| address.to_string())
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn cache_result(&mut self, address: IpAddr, name: Option<String>) {
        if self.cache.contains_key(&address) {
            return;
        }
        while self.cache.len() >= self.cache_capacity {
            if let Some(expired) = self.cache_order.pop_front() {
                self.cache.remove(&expired);
            }
        }
        self.cache_order.push_back(address);
        self.cache.insert(address, name);
    }
}

impl Drop for ReverseDns {
    fn drop(&mut self) {
        let mut queue = lock_queue(&self.queue);
        queue.stopped = true;
        queue.addresses.clear();
        self.queue.ready.notify_all();
    }
}

fn resolver_worker(
    queue: Arc<SharedQueue>,
    results: SyncSender<ResultMessage>,
    resolver: Arc<Resolver>,
) {
    loop {
        let address = {
            let mut state = lock_queue(&queue);
            while state.addresses.is_empty() && !state.stopped {
                state = queue
                    .ready
                    .wait(state)
                    .unwrap_or_else(|error| error.into_inner());
            }
            if state.stopped {
                return;
            }
            state.addresses.pop_front().unwrap()
        };
        let result = ResultMessage {
            address: address.address,
            generation: address.generation,
            name: resolver(address.address),
        };
        if results.send(result).is_err() {
            return;
        }
    }
}

impl Default for ReverseDns {
    fn default() -> Self {
        Self::new(false, 64, 512, reverse_lookup)
    }
}

fn reverse_lookup(address: IpAddr) -> Option<String> {
    let socket = SocketAddr::new(address, 0);
    let mut host = [0_i8; 1025];
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = match socket {
        SocketAddr::V4(socket) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(socket.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe { std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, raw) };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(socket) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: socket.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: socket.ip().octets(),
                },
                sin6_scope_id: socket.scope_id(),
            };
            unsafe { std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, raw) };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    let status = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            length,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if status != 0 {
        return None;
    }
    let hostname = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    hostname.to_str().ok().map(str::to_owned)
}
