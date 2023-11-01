# Pyile Application
![python] ![tkinter]


## About

This application showcases the <a href="https://github.com/nburnet1/pyile-protocol">Pyile protocol</a>, which is a central authenticating peer to peer messaging protocol. 



## Screenshots

#### ***Start Authentication***

<img src="https://github.com/nburnet1/img/blob/main/pyile/admin_start.png?raw=true" />

#### ***Authentication Status*** 

<img src="https://github.com/nburnet1/img/blob/main/pyile/auth_status.png?raw=true"/>

#### ***Logs***

<img src="https://github.com/nburnet1/img/blob/main/pyile/logs.png?raw=true" />

#### ***Messaging***

<img src="https://github.com/nburnet1/img/blob/main/pyile/messages.png?raw=true" />

* * *

## Configuration

Pyile can be configured using *config.json*. This allows users to quick start their connection by changing values such as their alias, default port, and allowed password attempts.

## Install

```
git clone https://github.com/nburnet1/pyile

cd pyile

python -m venv env_name
```
**Bash**
```
source env_name/bin/activate
```
**Windows**
```
env_name\Scripts\activate
```
**Install requirements**
```
pip install -r requirements.txt
```
**Help**
```
python main.py -h
```
**Example**
```
python main.py -g -a Noah -c config.json -S password -i 127.0.0.1 -p 4702 -j 4703
```


### Credits

[tkinter Theme](https://github.com/rdbende/Forest-ttk-theme)



[python]: https://img.shields.io/badge/-Python-yellow
[tkinter]: https://img.shields.io/badge/-tkinter-green
