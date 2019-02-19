# Getting Started

## Installing dependencies
First of all, you need everything that KISS needs in order to work correctly. Most things will be just a single command line.
### Python3
Most Unix distributions come already with a high version of Python3. If you don't have it, you can install it with:
```
sudo apt-get install python3
```
If this version is too low (< 3.6), you can instead do:
```
sudo apt-get install python3.6
```

### Scapy 2.4.0
KISS is based on a library called Scapy. In previous versions of KISS, you had to install the correct version, and move
some custom files needed for the proper functioning of KISS. Now, KISS comes with everything it needs, so you don't need to
lose time and space installing more things.

## Downloading KISS
After you installed the dependencies, you can easily download KISS in your current directory with:
```
git clone https://github.com/klesoft/KISS.git
```

Now KISS is ready to run. Before that, I recommend you to take a look at the [config file](https://klesoft.github.io/KISS/pages/config) and at some [examples](https://klesoft.github.io/KISS/pages/examples) files. Then, just go to KISS folder and run:
```
sudo python3 KISS.py
```
**Enjoy!**
