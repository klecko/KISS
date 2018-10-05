# Getting Started

## Installing dependencies
First of all, you need everything that KISS needs in order to work correctly. Most things will be just a single command line.
### Python3
As you know, KISS is programmed in Python3, so you need to install it. The default version works well.
```
sudo apt-get install python3
```

### Scapy 2.4.0+
KISS is based on a library called Scapy, which you will need to install. The easiest way is through pip:
```
sudo apt-get install python3-pip
pip3 install scapy
```
You can also try to install the latest release, and also the current development version, which you can see from [its GitHub directory](https://github.com/secdev/scapy).
If you want to do that, I recommend following [Scapy setup instructions](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x).


## Downloading KISS
After you installed the dependencies, you can easily download KISS in your current directory with:
```
git clone https://github.com/klesoft/KISS.git
```
Now you only need two more step. First, KISS needs some Scapy files to be modified. Those files are located in the `scapy_files` folder inside KISS. You will need to move the content of that folder to the source folder of scapy, which is usually located at `/usr/local/lib/pythonXXX/dist-packages/scapy`, where XXX is your Python version (i.e 3.6), or at `/home/NAME/.local/lib/pythonXXX/site-packages/scapy`, where NAME is your username.

After that, KISS is ready to run. Before that, I recommend you to take a look at the [config](https://klesoft.github.io/KISS/pages/config) and [verbose](https://klesoft.github.io/KISS/pages/verbose) files. Now, just go to KISS folder and run:
```
sudo python3 KISS.py
```
**Enjoy!**
