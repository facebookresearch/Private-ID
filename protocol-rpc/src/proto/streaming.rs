//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

extern crate crypto;
extern crate http;
extern crate log;
extern crate tonic;

use crypto::prelude::*;

use crate::proto::common::Payload;
use async_stream::stream;
use futures::Stream;
use std::cmp;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

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
