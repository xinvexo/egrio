//! A small set of request-owned futures. Dropping a resolver/dial immediately
//! drops every losing socket; no detached task can outlive the requesting flow.

use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::task::Poll;

pub(crate) struct Pending<'a, T> {
    futures: Vec<Pin<Box<dyn Future<Output = T> + Send + 'a>>>,
}

impl<'a, T> Pending<'a, T> {
    pub(crate) fn new() -> Self {
        Self {
            futures: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, future: impl Future<Output = T> + Send + 'a) {
        self.futures.push(Box::pin(future));
    }

    /// The same futures, each showing `seen` its result as it ends.
    pub(crate) fn inspected(self, seen: impl Fn(&T) + Clone + Send + 'a) -> Self
    where
        T: 'a,
    {
        Self {
            futures: self
                .futures
                .into_iter()
                .map(|future| {
                    let seen = seen.clone();
                    Box::pin(async move {
                        let result = future.await;
                        seen(&result);
                        result
                    }) as Pin<Box<dyn Future<Output = T> + Send + 'a>>
                })
                .collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.futures.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.futures.is_empty()
    }

    pub(crate) async fn next(&mut self) -> Option<T> {
        poll_fn(|cx| {
            for index in 0..self.futures.len() {
                if let Poll::Ready(result) = self.futures[index].as_mut().poll(cx) {
                    drop(self.futures.remove(index));
                    return Poll::Ready(Some(result));
                }
            }
            if self.futures.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
