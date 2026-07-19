// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{sync::Arc, vec::Vec};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::{ControlResponse, LocalControlChannel};
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse, PipeRequest, PipeResponse};
use litebox_broker_protocol::pipe::{
    CreatePipeRequest, CreatePipeResponse, PIPE_SHARED_MEMORY_REGION_SIZE, PIPE_SHARED_MEMORY_SIZE,
    ReadPipeRequest, ReadPipeSharedRequest, WritePipeRequest, WritePipeSharedRequest,
};
use litebox_broker_protocol::shared_memory::SharedMemory;

use crate::{BrokerLocal, BrokerLocalError, PipeSharedMemory, Result};

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned byte pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn create_pipe(
        &mut self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<CreatePipeResponse, Channel::Error> {
        let ControlResponse {
            response,
            shared_memory,
        } = self.request_with_shared_memory(BrokerRequest::Pipe(PipeRequest::Create(
            CreatePipeRequest {
                capacity,
                atomic_write_size,
            },
        )))?;
        match response {
            BrokerResponse::Pipe(PipeResponse::Create(response)) => {
                match (response.shared_memory, shared_memory) {
                    (false, None) => {}
                    (true, Some(memory)) => {
                        assert_eq!(
                            memory.len(),
                            PIPE_SHARED_MEMORY_SIZE,
                            "broker returned shared memory with an invalid size"
                        );
                        let memory = Arc::new(memory);
                        self.pipe_shared_memories.insert(
                            response.read_handle,
                            PipeSharedMemory {
                                memory: Arc::clone(&memory),
                                base: 0,
                                cursor: 0,
                            },
                        );
                        self.pipe_shared_memories.insert(
                            response.write_handle,
                            PipeSharedMemory {
                                memory,
                                base: PIPE_SHARED_MEMORY_REGION_SIZE,
                                cursor: 0,
                            },
                        );
                    }
                    _ => panic!("broker pipe response shared-memory attachment mismatch"),
                }
                Ok(response)
            }
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    /// Reads bytes from a broker-owned pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn read_pipe(
        &mut self,
        handle: ObjectHandle,
        length: u32,
    ) -> Result<Vec<u8>, Channel::Error> {
        if length as usize <= PIPE_SHARED_MEMORY_REGION_SIZE
            && self.pipe_shared_memories.contains_key(&handle)
        {
            return self.read_pipe_shared(handle, length);
        }
        match self.request_pipe(PipeRequest::Read(ReadPipeRequest { handle, length }))? {
            PipeResponse::Read(response) => Ok(response.data),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    /// Writes bytes to a broker-owned pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn write_pipe(
        &mut self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        if data.len() <= PIPE_SHARED_MEMORY_REGION_SIZE
            && self.pipe_shared_memories.contains_key(&handle)
        {
            return self.write_pipe_shared(handle, data);
        }
        match self.request_pipe(PipeRequest::Write(WritePipeRequest {
            handle,
            data: data.to_vec(),
        }))? {
            PipeResponse::Write(response) => Ok(response.written as usize),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    fn read_pipe_shared(
        &mut self,
        handle: ObjectHandle,
        length: u32,
    ) -> Result<Vec<u8>, Channel::Error> {
        let (memory, base, offset) = {
            let shared = self
                .pipe_shared_memories
                .get(&handle)
                .expect("shared pipe handle disappeared");
            let length = length as usize;
            let offset = if shared.cursor + length > PIPE_SHARED_MEMORY_REGION_SIZE {
                0
            } else {
                shared.cursor
            };
            (Arc::clone(&shared.memory), shared.base, offset)
        };
        let offset_u32 = offset
            .try_into()
            .expect("shared pipe ring offset must fit in u32");
        let mut data = Vec::new();
        data.try_reserve_exact(length as usize).map_err(|_| {
            BrokerLocalError::Broker(litebox_broker_protocol::error::ErrorCode::OutOfMemory)
        })?;
        data.resize(length as usize, 0);
        let response = self.request_pipe(PipeRequest::ReadShared(ReadPipeSharedRequest {
            handle,
            offset: offset_u32,
            length,
        }))?;
        let PipeResponse::ReadShared(response) = response else {
            panic!("broker returned unexpected shared pipe read response: {response:?}");
        };
        assert!(
            response.read <= length,
            "broker returned oversized pipe read"
        );
        let read = response.read as usize;
        data.truncate(read);
        memory
            .read(base + offset, &mut data)
            .expect("validated shared pipe read range must be accessible");
        self.pipe_shared_memories
            .get_mut(&handle)
            .expect("shared pipe handle disappeared")
            .cursor = (offset + read) % PIPE_SHARED_MEMORY_REGION_SIZE;
        Ok(data)
    }

    fn write_pipe_shared(
        &mut self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        let (memory, base, offset) = {
            let shared = self
                .pipe_shared_memories
                .get(&handle)
                .expect("shared pipe handle disappeared");
            let offset = if shared.cursor + data.len() > PIPE_SHARED_MEMORY_REGION_SIZE {
                0
            } else {
                shared.cursor
            };
            (Arc::clone(&shared.memory), shared.base, offset)
        };
        memory
            .write(base + offset, data)
            .expect("validated shared pipe write range must be accessible");
        let response = self.request_pipe(PipeRequest::WriteShared(WritePipeSharedRequest {
            handle,
            offset: offset
                .try_into()
                .expect("shared pipe ring offset must fit in u32"),
            length: data
                .len()
                .try_into()
                .expect("shared pipe transfer length must fit in u32"),
        }))?;
        let PipeResponse::WriteShared(response) = response else {
            panic!("broker returned unexpected shared pipe write response: {response:?}");
        };
        let written = response.written as usize;
        assert!(
            written <= data.len(),
            "broker returned oversized shared pipe write"
        );
        self.pipe_shared_memories
            .get_mut(&handle)
            .expect("shared pipe handle disappeared")
            .cursor = (offset + written) % PIPE_SHARED_MEMORY_REGION_SIZE;
        Ok(written)
    }

    fn request_pipe(&mut self, request: PipeRequest) -> Result<PipeResponse, Channel::Error> {
        match self.request(BrokerRequest::Pipe(request))? {
            BrokerResponse::Pipe(response) => Ok(response),
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResponse::ObjectClosed
            | BrokerResponse::Readiness(_)
            | BrokerResponse::Event(_)) => {
                panic!("broker returned unexpected pipe response: {response:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
    use litebox_broker_protocol::pipe::{
        ReadPipeResponse, ReadPipeSharedResponse, WritePipeResponse,
    };
    use litebox_broker_protocol::shared_memory::SharedMemoryError;

    #[test]
    fn pipe_uses_attached_shared_memory_for_data_operations() {
        let read_handle = ObjectHandle(1);
        let write_handle = ObjectHandle(2);
        let memory = TestSharedMemory::new(PIPE_SHARED_MEMORY_SIZE);
        let channel = ScriptedChannel::new([
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
                    read_handle,
                    write_handle,
                    shared_memory: true,
                })),
                shared_memory: Some(memory.clone()),
            },
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::WriteShared(WritePipeResponse {
                    written: 3,
                })),
                shared_memory: None,
            },
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::ReadShared(ReadPipeSharedResponse {
                    read: 2,
                })),
                shared_memory: None,
            },
        ]);
        let mut local = BrokerLocal::negotiate(channel).unwrap();

        local.create_pipe(64, 16).unwrap();
        assert_eq!(local.write_pipe(write_handle, &[1, 2, 3]).unwrap(), 3);
        let mut staged = [0; 3];
        memory
            .read(PIPE_SHARED_MEMORY_REGION_SIZE, &mut staged)
            .unwrap();
        assert_eq!(staged, [1, 2, 3]);

        memory.write(0, &[4, 5]).unwrap();
        assert_eq!(local.read_pipe(read_handle, 2).unwrap(), [4, 5]);
        assert_eq!(
            local.channel.sent_requests,
            [
                BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                    capacity: 64,
                    atomic_write_size: 16,
                })),
                BrokerRequest::Pipe(PipeRequest::WriteShared(WritePipeSharedRequest {
                    handle: write_handle,
                    offset: 0,
                    length: 3,
                })),
                BrokerRequest::Pipe(PipeRequest::ReadShared(ReadPipeSharedRequest {
                    handle: read_handle,
                    offset: 0,
                    length: 2,
                })),
            ]
        );
    }

    #[test]
    fn pipe_uses_inline_operations_without_shared_memory() {
        let read_handle = ObjectHandle(1);
        let write_handle = ObjectHandle(2);
        let channel = ScriptedChannel::new([
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
                    read_handle,
                    write_handle,
                    shared_memory: false,
                })),
                shared_memory: None,
            },
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::Write(WritePipeResponse {
                    written: 3,
                })),
                shared_memory: None,
            },
            ControlResponse {
                response: BrokerResponse::Pipe(PipeResponse::Read(ReadPipeResponse {
                    data: Vec::from([4, 5]),
                })),
                shared_memory: None,
            },
        ]);
        let mut local = BrokerLocal::negotiate(channel).unwrap();

        local.create_pipe(64, 16).unwrap();
        assert_eq!(local.write_pipe(write_handle, &[1, 2, 3]).unwrap(), 3);
        assert_eq!(local.read_pipe(read_handle, 2).unwrap(), [4, 5]);
        assert!(matches!(
            &local.channel.sent_requests[1],
            BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest { handle, data }))
                if *handle == write_handle && data == &[1, 2, 3]
        ));
        assert_eq!(
            local.channel.sent_requests[2],
            BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: read_handle,
                length: 2,
            }))
        );
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct ScriptedChannel {
        responses: VecDeque<ControlResponse<TestSharedMemory>>,
        sent_requests: Vec<BrokerRequest>,
    }

    impl ScriptedChannel {
        fn new(responses: impl IntoIterator<Item = ControlResponse<TestSharedMemory>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                sent_requests: Vec::new(),
            }
        }
    }

    impl LocalControlChannel for ScriptedChannel {
        type Error = Infallible;
        type SharedMemory = TestSharedMemory;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_requests.push(request.clone());
            Ok(())
        }

        fn recv_response(
            &mut self,
        ) -> core::result::Result<Option<ControlResponse<Self::SharedMemory>>, Self::Error>
        {
            Ok(self.responses.pop_front())
        }
    }
}
