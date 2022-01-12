/*
** Copyright 2021 Bloomberg Finance L.P.
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;
use tokio::runtime::Builder;

mod client;
mod server;

#[derive(Debug, Parser, Clone)]
struct PerfTesterOpts {
    #[clap(long, default_value = "amqp://localhost:5672/")]
    address: String,

    #[clap(long, default_value_t = 10)]
    clients: usize,

    #[clap(long, default_value_t = 100)]
    message_size: usize,

    #[clap(long, default_value_t = 10)]
    num_messages: usize,

    #[clap(long, default_value_t = 50)]
    max_threads: usize,

    #[clap(long)]
    listen_address: SocketAddr,

    #[clap(long)]
    listen_cert: Option<PathBuf>,

    #[clap(long)]
    listen_key: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = PerfTesterOpts::parse();

    let start = Instant::now();

    let mut success = 0;

    {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(opts.max_threads)
            .build()
            .unwrap();

        let opts = opts.clone();
        runtime.block_on(async {
            log::info!("Starting performance test of amqpprox");

            let address = opts.listen_address;
            let _server = if let (Some(listen_cert), Some(listen_key)) =
                (opts.listen_cert, opts.listen_key)
            {
                log::info!("Starting TLS dummy amqp server");
                tokio::spawn(async move {
                    server::run_tls_server(address, &listen_cert, &listen_key).await
                })
            } else {
                log::info!("Starting non-TLS dummy amqp server");
                tokio::spawn(async move { server::run_server(address).await })
            };

            tokio::time::sleep(std::time::Duration::from_millis(1000)).await; // TODO

            let mut handles = Vec::new();
            for _ in 0..opts.clients {
                let address = opts.address.clone();
                let message_size = opts.message_size;
                let num_messages = opts.num_messages;

                let handle = tokio::task::spawn_blocking(move || crate::client::run_sync_client(address, message_size, num_messages));
                handles.push(handle);
            }

            for handle in handles {
                match handle.await.unwrap() {
                    Ok(_) => success += 1,
                    Err(err) => log::error!("Client failed: {:?}", err),
                }
            }
        });
    }

    if success != opts.clients {
        println!("{} clients were not fully successful. Check the logs to see if this will impact perf results", opts.clients - success);
    }

    let duration = start.elapsed();
    let total_bytes = opts.clients * opts.num_messages * opts.message_size;
    println!(
        "{} clients and {}KB in {}seconds",
        opts.clients,
        total_bytes / 1000,
        duration.as_secs_f64()
    );

    let clients_per_sec = opts.clients as f64 / duration.as_secs_f64();
    let bytes_per_sec = total_bytes as f64 / duration.as_secs_f64();

    println!(
        "{} connections/second, {} MB/second",
        clients_per_sec,
        bytes_per_sec / 1000f64 / 1000f64
    );

    //server.await??;
    Ok(())
}
