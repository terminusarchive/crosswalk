use std::{
    io::{self, ErrorKind, Read},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MICROSECOND_MAGIC: u32 = 0xa1b2_c3d4;
const NANOSECOND_MAGIC: u32 = 0xa1b2_3c4d;
const FILE_HEADER_BYTES: usize = 24;
const PACKET_HEADER_BYTES: usize = 16;
/// dumpcap's default snapshot length; a longer packet means a corrupt stream.
const MAX_PACKET_BYTES: u32 = 262_144;

#[derive(Debug, PartialEq, Eq)]
pub struct StreamPacket {
    pub data: Vec<u8>,
    pub captured_at: SystemTime,
}

/// Packets read from a little-endian pcap stream, such as dumpcap writes to a pipe.
pub struct PcapStream<R> {
    reader: R,
    link_type: i32,
    fraction_nanos: u32,
}

impl<R: Read> PcapStream<R> {
    pub fn new(mut reader: R) -> Result<Self, String> {
        let mut header = [0; FILE_HEADER_BYTES];
        reader
            .read_exact(&mut header)
            .map_err(|error| format!("pcap stream ended in its file header: {error}"))?;
        let fraction_nanos = match read_u32(&header, 0) {
            MICROSECOND_MAGIC => 1_000,
            NANOSECOND_MAGIC => 1,
            magic => return Err(format!("pcap stream has unknown magic {magic:08x}")),
        };
        let link_type = i32::try_from(read_u32(&header, 20))
            .map_err(|_| "pcap stream has an out of range link type".to_string())?;
        Ok(Self {
            reader,
            link_type,
            fraction_nanos,
        })
    }

    pub fn link_type(&self) -> i32 {
        self.link_type
    }

    /// The next packet, or `None` when the stream ends between packets.
    pub fn next_packet(&mut self) -> Result<Option<StreamPacket>, String> {
        let mut header = [0; PACKET_HEADER_BYTES];
        let read = read_up_to(&mut self.reader, &mut header)
            .map_err(|error| format!("pcap stream could not be read: {error}"))?;
        if read == 0 {
            return Ok(None);
        }
        if read < PACKET_HEADER_BYTES {
            return Err("pcap stream ended in a packet header".to_string());
        }
        let length = read_u32(&header, 8);
        if length > MAX_PACKET_BYTES {
            return Err(format!(
                "pcap packet of {length} bytes is larger than {MAX_PACKET_BYTES}"
            ));
        }
        let mut data = vec![0; length as usize];
        self.reader
            .read_exact(&mut data)
            .map_err(|error| format!("pcap stream ended in a packet: {error}"))?;
        let since_epoch = Duration::new(
            u64::from(read_u32(&header, 0)),
            read_u32(&header, 4).saturating_mul(self.fraction_nanos),
        );
        Ok(Some(StreamPacket {
            data,
            captured_at: UNIX_EPOCH + since_epoch,
        }))
    }
}

/// Reads until `buffer` is full or the stream ends; returns how many bytes arrived.
fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    const NANOSECOND_MAGIC: u32 = 0xa1b2_3c4d;
    const MICROSECOND_MAGIC: u32 = 0xa1b2_c3d4;

    fn file_header(magic: u32, link_type: u32) -> Vec<u8> {
        let mut bytes = magic.to_le_bytes().to_vec();
        bytes.extend([2, 0, 4, 0]);
        bytes.extend([0; 8]);
        bytes.extend(262_144u32.to_le_bytes());
        bytes.extend(link_type.to_le_bytes());
        bytes
    }

    fn packet_record(seconds: u32, fraction: u32, data: &[u8]) -> Vec<u8> {
        let length = (data.len() as u32).to_le_bytes();
        let mut bytes = seconds.to_le_bytes().to_vec();
        bytes.extend(fraction.to_le_bytes());
        bytes.extend(length);
        bytes.extend(length);
        bytes.extend(data);
        bytes
    }

    fn stream(parts: &[Vec<u8>]) -> Result<PcapStream<std::io::Cursor<Vec<u8>>>, String> {
        PcapStream::new(std::io::Cursor::new(parts.concat()))
    }

    #[test]
    fn nanosecond_stream_gives_link_type_and_packets_with_times() {
        let mut packets = stream(&[
            file_header(NANOSECOND_MAGIC, 276),
            packet_record(1_000, 123_456_789, b"first"),
            packet_record(1_001, 5, b"second!"),
        ])
        .unwrap();

        assert_eq!(packets.link_type(), 276);
        let first = packets.next_packet().unwrap().unwrap();
        assert_eq!(first.data, b"first");
        assert_eq!(
            first.captured_at,
            UNIX_EPOCH + Duration::new(1_000, 123_456_789)
        );
        let second = packets.next_packet().unwrap().unwrap();
        assert_eq!(second.data, b"second!");
        assert_eq!(second.captured_at, UNIX_EPOCH + Duration::new(1_001, 5));
        assert_eq!(packets.next_packet().unwrap(), None);
    }

    #[test]
    fn microsecond_stream_gives_times_to_the_microsecond() {
        let mut packets = stream(&[
            file_header(MICROSECOND_MAGIC, 276),
            packet_record(1_000, 123_456, b"data"),
        ])
        .unwrap();

        let packet = packets.next_packet().unwrap().unwrap();
        assert_eq!(
            packet.captured_at,
            UNIX_EPOCH + Duration::new(1_000, 123_456_000)
        );
    }

    #[test]
    fn unknown_magic_is_an_error() {
        let error = stream(&[file_header(0xdead_beef, 276)]).err().unwrap();
        assert!(error.contains("deadbeef"), "{error}");
    }

    #[test]
    fn stream_ending_inside_the_file_header_is_an_error() {
        let header = file_header(NANOSECOND_MAGIC, 276);
        assert!(stream(&[header[..10].to_vec()]).is_err());
    }

    #[test]
    fn stream_ending_inside_a_packet_header_is_an_error() {
        let record = packet_record(1, 1, b"data");
        let mut packets =
            stream(&[file_header(NANOSECOND_MAGIC, 276), record[..7].to_vec()]).unwrap();
        assert!(packets.next_packet().is_err());
    }

    #[test]
    fn stream_ending_inside_a_packet_is_an_error() {
        let record = packet_record(1, 1, b"data");
        let mut packets = stream(&[
            file_header(NANOSECOND_MAGIC, 276),
            record[..record.len() - 1].to_vec(),
        ])
        .unwrap();
        assert!(packets.next_packet().is_err());
    }

    #[test]
    fn packet_longer_than_the_bound_is_an_error_without_reading_it() {
        let mut record = packet_record(1, 1, b"");
        record[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut packets = stream(&[file_header(NANOSECOND_MAGIC, 276), record]).unwrap();
        let error = packets.next_packet().unwrap_err();
        assert!(error.contains("4294967295"), "{error}");
    }
}
