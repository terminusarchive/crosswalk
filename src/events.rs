use std::collections::VecDeque;

/// Most events kept; the oldest go first.
pub const EVENT_LIMIT: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Neighbour,
    Port,
    Firewall,
    Connection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventLevel {
    Normal,
    Warning,
    Danger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkEvent {
    /// Local wall-clock `HH:MM` when the event was logged, if the clock could be read.
    pub clock: Option<String>,
    pub kind: EventKind,
    pub text: String,
    pub level: EventLevel,
}

/// The newest `EVENT_LIMIT` events, newest first.
#[derive(Debug, Default)]
pub struct EventLog {
    events: VecDeque<NetworkEvent>,
}

impl EventLog {
    pub fn push(&mut self, event: NetworkEvent) {
        self.events.push_front(event);
        self.events.truncate(EVENT_LIMIT);
    }

    /// Newest first.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &NetworkEvent> {
        self.events.iter()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
