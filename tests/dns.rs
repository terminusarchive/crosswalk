use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use crosswalk::dns::ReverseDns;

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn wait_for_name(dns: &mut ReverseDns, destination: IpAddr) -> Option<String> {
    for _ in 0..100 {
        dns.poll();
        if let Some(name) = dns.name(destination) {
            return Some(name.to_owned());
        }
        thread::sleep(Duration::from_millis(2));
    }
    None
}

#[test]
fn visible_destinations_keep_numeric_fallback_and_cache_success_and_failure() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver_calls = calls.clone();
    let mut dns = ReverseDns::new(true, 4, 4, move |address| {
        resolver_calls.fetch_add(1, Ordering::SeqCst);
        (address == ip("198.51.100.7")).then(|| "ptr.example".to_owned())
    });
    let named = ip("198.51.100.7");
    let missing = ip("203.0.113.8");

    assert_eq!(dns.name(named), None);
    assert_eq!(dns.display_name(named), "198.51.100.7");
    dns.schedule_visible([named, named, missing]);
    assert_eq!(
        wait_for_name(&mut dns, named).as_deref(),
        Some("ptr.example")
    );
    assert_eq!(dns.name(missing), None);
    dns.schedule_visible([missing]);
    thread::sleep(Duration::from_millis(10));
    dns.poll();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn disabling_suppresses_new_requests_and_discards_late_results() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let mut dns = ReverseDns::new(true, 2, 2, move |_| {
        started_tx.send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
        Some("late.example".to_owned())
    });
    let destination = ip("198.51.100.9");
    dns.schedule_visible([destination]);
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    dns.set_enabled(false);
    release_tx.send(()).unwrap();
    thread::sleep(Duration::from_millis(10));
    dns.poll();
    dns.schedule_visible([destination]);
    assert_eq!(dns.name(destination), None);
    assert_eq!(dns.pending(), 0);
}

#[test]
fn result_from_before_disable_cannot_replace_a_new_lookup_after_reenable() {
    let (first_started_tx, first_started_rx) = mpsc::channel();
    let (release_first_tx, release_first_rx) = mpsc::channel();
    let (first_finished_tx, first_finished_rx) = mpsc::channel();
    let release_first_rx = std::sync::Mutex::new(release_first_rx);
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver_calls = calls.clone();
    let mut dns = ReverseDns::new(true, 2, 2, move |_| {
        if resolver_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            first_started_tx.send(()).unwrap();
            release_first_rx.lock().unwrap().recv().unwrap();
            first_finished_tx.send(()).unwrap();
            Some("stale.example".to_owned())
        } else {
            Some("current.example".to_owned())
        }
    });
    let destination = ip("198.51.100.19");

    dns.schedule_visible([destination]);
    first_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    dns.set_enabled(false);
    dns.set_enabled(true);
    release_first_tx.send(()).unwrap();
    first_finished_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    for _ in 0..10 {
        dns.poll();
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(dns.name(destination), None);
    dns.schedule_visible([destination]);
    assert_eq!(
        wait_for_name(&mut dns, destination).as_deref(),
        Some("current.example")
    );
}

#[test]
fn repeated_visible_destinations_coalesce_while_lookup_is_pending() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver_calls = calls.clone();
    let mut dns = ReverseDns::new(true, 1, 2, move |_| {
        resolver_calls.fetch_add(1, Ordering::SeqCst);
        Some("shared.example".to_owned())
    });
    let destination = ip("198.51.100.10");
    dns.schedule_visible([destination]);
    dns.schedule_visible([destination, destination]);
    assert_eq!(
        wait_for_name(&mut dns, destination).as_deref(),
        Some("shared.example")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn queue_and_cache_are_bounded_and_drop_does_not_wait_for_resolver() {
    let (started_tx, started_rx) = mpsc::channel();
    let mut dns = ReverseDns::new(true, 1, 1, move |_| {
        started_tx.send(()).unwrap();
        thread::park();
        Some("never.example".to_owned())
    });
    // Both workers are held inside the resolver before the queue is filled, so what
    // is pending does not depend on how fast a worker takes a request off the queue.
    for address in ["198.51.100.11", "198.51.100.12"] {
        dns.schedule_visible([ip(address)]);
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert_eq!(dns.pending(), 2);
    // A queue of one holds the third; the fourth and fifth find the bound reached
    // (the queue plus the two requests in the workers) and are dropped.
    dns.schedule_visible([
        ip("198.51.100.13"),
        ip("198.51.100.14"),
        ip("198.51.100.15"),
    ]);
    assert_eq!(dns.pending(), 3);
    let poll_start = std::time::Instant::now();
    dns.poll();
    assert!(poll_start.elapsed() < Duration::from_millis(100));

    let start = std::time::Instant::now();
    drop(dns);
    assert!(start.elapsed() < Duration::from_millis(100));
}

#[test]
fn cache_capacity_evicts_old_entries_for_later_visible_destinations() {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver_calls = calls.clone();
    let mut dns = ReverseDns::new(true, 4, 1, move |address| {
        resolver_calls.fetch_add(1, Ordering::SeqCst);
        Some(address.to_string())
    });
    let first = ip("198.51.100.21");
    let second = ip("198.51.100.22");

    dns.schedule_visible([first]);
    assert_eq!(
        wait_for_name(&mut dns, first).as_deref(),
        Some("198.51.100.21")
    );
    dns.schedule_visible([second]);
    assert_eq!(
        wait_for_name(&mut dns, second).as_deref(),
        Some("198.51.100.22")
    );
    dns.schedule_visible([first]);
    assert_eq!(
        wait_for_name(&mut dns, first).as_deref(),
        Some("198.51.100.21")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
