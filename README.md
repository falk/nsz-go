# nsz-go

Fast NSP to NSZ compression tool written in Go with parallel zstd compression.

## Usage

```bash
nsz-go [-k prod.keys] [-l 18] <file.nsp>
```

Requires `prod.keys` in current directory or `~/.switch/prod.keys`.

Ported from [nicoboss/nsz](https://github.com/nicoboss/nsz) (Python).

Note: This project was built with the assistance of an LLM.
