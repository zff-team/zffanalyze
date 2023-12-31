# zffanalyze

```zffanalyze``` is a command line utility to analyze zff images.

# Installation

## Install via snapd

```bash
sudo snap install zffanalyze
```

## Install via cargo

```bash
$ cargo install zffanalyze
```

## build yourself

### Prerequisites
First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffanalyze```.

After that you still need the gcc, which you can install as follows (depends on the distribution):
###### Debian/Ubuntu
```bash
$ sudo apt-get install gcc libacl1-dev
```
###### Fedora
```bash
$ sudo dnf install gcc libacl-devel
```

### build via cargo

Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffanalyze] $ cargo build --release
```

# Usage

To show the metadata of the given zff file, execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01>
```

If you want to perform an integrity check, you can simply execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01> -c
```

If you want to determine the authenticity of the data with an existing public key, then execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01> -k "c9IvuVj4lnGVSXR5Azx8SAyqQBpeHMKpB/4v8/Cj4Ew="
```