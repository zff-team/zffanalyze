# zffanalyze

```zffanalyze``` is a command line utility to analyze zff images.

# Installation
## Prerequisites
First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffanalyze```.

After that you still need the gcc, which you can install as follows (depends on the distribution):
###### Debian/Ubuntu
```bash
$ sudo apt-get install gcc
```
###### Fedora
```bash
$ sudo dnf install gcc
```

Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffanalyze] $ cargo build --release
```
Or you can install the tool directly from crates.io:
```bash
$ cargo install zffanalyze
```

# Usage

Use ```zffanalyze -i <YOUR_ZFF_IMAGE.z01>``` show the metadata of the given zff file.