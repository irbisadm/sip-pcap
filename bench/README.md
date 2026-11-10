# Benchmarks

How long `buildLadder()` takes on a large capture, and what it costs a page to get the
result out of a Web Worker. Not part of the package, `npm test` or CI.

## What is measured

- **The capture.** `gen-capture.mjs` repeats the sample call (`proxyCallFlow()`, 13
  messages through a proxy) 4,000 times. Each copy has its own Call-ID and starts 1 s
  after the previous one, so the calls overlap. The result is about 26 MB with 52,000
  SIP messages.
- **Node.js.** `node-bench.mjs` times `buildLadder()` after a warm-up and, through
  `node-cold.sh`, as the first call in a fresh process. A fresh Web Worker runs it
  the same way, with a cold JIT. It also times `structuredClone()` of the full result
  and of the summary, because `postMessage` uses the same serializer.
- **The browser.** `browser-bench.mjs` serves `www/` locally and drives headless
  Chrome or Chromium through two variants:
  - **(a) result posted whole:** the worker posts the full `buildLadder()` result.
  - **(b) result kept in the worker:** the worker posts the call list only
    (`summarizeLadder()`), and the page then asks for the messages of one call.

  Both variants draw the same DOM: the summary line, the first 200 calls of the list
  and the ladder of the first call. Each run uses a fresh tab and a fresh worker, and
  the order of the variants alternates.
  - The clock starts right before the bytes are posted to the worker.
  - "Drawn" means the ladder is in the DOM, then a `requestAnimationFrame`, then a task
    posted through a `MessageChannel`: the main thread has finished the frame that
    first shows the ladder.
  - Main-thread pauses are measured three ways: the Long Tasks API, Long Animation
    Frames, and a 16 ms interval timer.
- **The DevTools trace.** `trace-bench.mjs` finds the longest main-thread task, tasks
  under 50 ms included, and how much of it is garbage collection.
- **The live page.** `live-bench.mjs` loads the same file into
  https://webrtc.page/tools/sip-ladder through its file input. Here the clock starts at
  the input's `change` event, so reading the file is included.

## Running

```sh
npm run build      # in the repository root: the benchmarks import ../dist
cd bench
npm install
./run-all.sh       # or step by step: npm run capture, npm run node, npm run browser, …
```

Set `BROWSER=/path/to/chrome` if the browser is not at `/usr/bin/google-chrome-stable`
(or `/usr/bin/chromium` with the `chromium` argument). Browsers run headless with their
own profile in this folder. Results go to `results/` as JSON with every run.

## Results, 2026-11-10

Intel Core i9-13900H, Linux 7.2, Node.js 24.22.2, headless Google Chrome 157.0.8103.38,
sip-pcap 0.2.0. Each cell is the medians of two independent runs of this harness, 20
runs per variant each.

| 26 MB, 4,000 calls | result posted whole | result kept in the worker |
|---|---|---|
| longest main-thread task | 246–250 ms | none over 50 ms (14 ms in a trace) |
| bytes posted → first ladder drawn | 0.96–0.98 s | 0.61–0.62 s |
| `buildLadder()` in the worker | 566–576 ms | 562–569 ms |
| `postMessage` of the result in the worker | 125–129 ms | 2 ms |

`buildLadder()` in Node.js took 490–523 ms warm and 666–686 ms cold. The live page drew
the first ladder 645–649 ms after `change`, with no task over 50 ms. Chromium 156 was
10–15% slower on every number.

What these numbers do not cover:

- **Headless rendering.** There is no vsync and no GPU compositing.
- **CPU state.** The CPU frequency was not fixed. On a hybrid CPU a worker that lands on
  an efficiency core parses about twice as slowly.
- **The local page.** It is plain DOM, not the Vue page of the live tool.
- **The capture.** It is synthetic: no RTP, TCP, fragments or retransmissions.
