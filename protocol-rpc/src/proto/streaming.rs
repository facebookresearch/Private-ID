//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::cmp;

use async_stream::stream;
use crypto::prelude::*;
use futures::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

use crate::proto::common::Payload;

fn chunks_count<T>(data: &[T]) -> usize {
    cmp::max(32_usize, data.len() / 2000_usize)
}

pub fn send_data(data: TPayload) -> Request<impl Stream<Item = Payload>> {
    let chunk_count = chunks_count(data.as_ref());
    let s = stream! {
        for chunk in data.chunks(chunk_count).into_iter() {
            let pl = chunk.iter().map(|x| x.buffer.clone()).collect::<Vec<Vec<u8>>>();
            yield Payload { payload: pl}
         }
    };
    Request::new(s)
}

pub type TPayloadStream = ReceiverStream<Result<Payload, Status>>;

pub async fn read_from_stream(strm: &mut Streaming<Payload>) -> Result<TPayload, Status> {
    let mut res: TPayload = Vec::default();
    //todo: consider collect with seq exact
    while let Some(payload) = strm.message().await? {
        res.extend(payload.payload.iter().map(|x| ByteBuffer::from_slice(x)));
    }
    Ok(res)
}

pub fn write_to_stream(payload: TPayload) -> Response<TPayloadStream> {
    let (tx, rx) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        for pl in payload.chunks(chunks_count(&payload)).into_iter() {
            let z = pl
                .iter()
                .map(|c| c.buffer.clone())
                .collect::<Vec<Vec<u8>>>();
            let m = Payload { payload: z };
            tx.send(Ok(m)).await.unwrap();
        }
    });
    Response::new(ReceiverStream::new(rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_data() {
        let data = vec![
            ByteBuffer {
                buffer: vec![
                    200, 135, 56, 19, 5, 207, 16, 147, 198, 229, 224, 111, 97, 119, 247, 238, 48,
                    209, 55, 188, 30, 178, 53, 4, 110, 27, 182, 220, 156, 57, 53, 63,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    102, 237, 233, 208, 207, 235, 165, 5, 177, 27, 168, 233, 239, 69, 163, 80, 155,
                    2, 85, 192, 182, 25, 20, 189, 118, 5, 225, 153, 13, 254, 201, 40,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    48, 54, 39, 197, 69, 34, 214, 167, 225, 117, 64, 223, 51, 164, 33, 208, 18,
                    108, 38, 248, 215, 189, 94, 180, 82, 105, 196, 43, 189, 2, 220, 6,
                ],
            },
            ByteBuffer {
                buffer: vec![
                    228, 188, 46, 30, 21, 100, 156, 96, 162, 185, 103, 149, 89, 159, 81, 67, 119,
                    112, 0, 174, 99, 188, 74, 7, 13, 236, 98, 48, 50, 145, 156, 50,
                ],
            },
        ];

        let p = Payload::from(&data);
        let tp = TPayload::from(&p);
        send_data(tp);
    }
}
