//! A scripted byte stream, for exercising transports without a network.
//!
//! Transport adapters are written against [`ByteStream`] rather than a
//! socket, so the protocol logic can be driven by recorded server behaviour.
//! This module provides that recording: a stream that replays scripted
//! responses and remembers what was written.
//!
//! It lives in the library rather than in a test file because two adapters
//! need it, and a shared fixture that each crate copies drifts apart.

use std::collections::VecDeque;

use crate::transport::{ByteStream, TransportError};

/// A stream that replays scripted server responses.
#[derive(Debug, Default)]
pub struct ScriptedStream {
    /// Responses the server will send, in order.
    responses: VecDeque<String>,
    /// Bytes the client has written.
    pub written: Vec<u8>,
    /// Whether the stream has been closed.
    pub closed: bool,
    /// When set, reading fails with this error instead of replaying.
    pub failure: Option<TransportError>,
}

impl ScriptedStream {
    /// Create a stream that will send the given responses, in order.
    pub fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            responses: responses.into_iter().map(Into::into).collect(),
            written: Vec::new(),
            closed: false,
            failure: None,
        }
    }

    /// Make the stream fail with the given error on the next read.
    pub fn failing(mut self, error: TransportError) -> Self {
        self.failure = Some(error);
        self
    }

    /// Everything the client wrote, as a string.
    pub fn written_text(&self) -> String {
        String::from_utf8_lossy(&self.written).into_owned()
    }

    /// The next scripted response, if any.
    fn next_response(&mut self) -> Result<String, TransportError> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.responses
            .pop_front()
            .ok_or(TransportError::Unavailable)
    }
}

impl ByteStream for ScriptedStream {
    fn read_line(&mut self, limit: u64) -> Result<String, TransportError> {
        let response = self.next_response()?;
        if response.len() as u64 > limit {
            return Err(TransportError::TooLarge { limit });
        }
        Ok(response)
    }

    fn read_exact(&mut self, length: u64) -> Result<Vec<u8>, TransportError> {
        let response = self.next_response()?;
        let bytes = response.into_bytes();
        if bytes.len() as u64 != length {
            // A short read would parse as a different message, so it is an
            // error rather than a partial result.
            return Err(TransportError::Protocol("short literal read".to_owned()));
        }
        Ok(bytes)
    }

    fn write(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.written.extend_from_slice(data);
        Ok(())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.closed = true;
        Ok(())
    }
}

/// A stream that returns a response for every line, cycling through a script.
///
/// Some protocols read a line at a time and answer it, so a fixed script is
/// not enough to exercise them.
#[derive(Debug, Default)]
pub struct RepeatingStream {
    /// Responses to return, in order, repeating once exhausted.
    pub responses: Vec<String>,
    /// Bytes the client has written.
    pub written: Vec<u8>,
    /// How many responses have been returned so far.
    pub served: usize,
}

impl RepeatingStream {
    /// Create a stream that answers with the given responses, repeating.
    pub fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            responses: responses.into_iter().map(Into::into).collect(),
            written: Vec::new(),
            served: 0,
        }
    }

    /// Everything the client wrote, as a string.
    pub fn written_text(&self) -> String {
        String::from_utf8_lossy(&self.written).into_owned()
    }
}

impl ByteStream for RepeatingStream {
    fn read_line(&mut self, limit: u64) -> Result<String, TransportError> {
        if self.responses.is_empty() {
            return Err(TransportError::Unavailable);
        }
        let index = self.served % self.responses.len();
        self.served += 1;
        let response = self.responses[index].clone();
        if response.len() as u64 > limit {
            return Err(TransportError::TooLarge { limit });
        }
        Ok(response)
    }

    fn read_exact(&mut self, length: u64) -> Result<Vec<u8>, TransportError> {
        let index = self.served % self.responses.len().max(1);
        self.served += 1;
        let bytes = self
            .responses
            .get(index)
            .cloned()
            .unwrap_or_default()
            .into_bytes();
        if bytes.len() as u64 != length {
            return Err(TransportError::Protocol("short literal read".to_owned()));
        }
        Ok(bytes)
    }

    fn write(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.written.extend_from_slice(data);
        Ok(())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scripted_stream_replays_in_order() {
        let mut stream = ScriptedStream::new(["* OK ready", "* CAPABILITY IMAP4rev1"]);
        assert_eq!(stream.read_line(1024).unwrap(), "* OK ready");
        assert_eq!(stream.read_line(1024).unwrap(), "* CAPABILITY IMAP4rev1");
        assert!(stream.read_line(1024).is_err());
    }

    #[test]
    fn a_response_over_the_limit_is_an_error() {
        let mut stream = ScriptedStream::new(["a line that is too long"]);
        assert!(matches!(
            stream.read_line(4),
            Err(TransportError::TooLarge { .. })
        ));
    }

    #[test]
    fn written_bytes_are_remembered() {
        let mut stream = ScriptedStream::new(Vec::<String>::new());
        stream.write(b"NOOP\r\n").unwrap();
        assert_eq!(stream.written_text(), "NOOP\r\n");
    }
}
