# FSND Project: Catalog
#### by Omotayo Madein

## Description

This is a project for [Udacity Full Stack Web Developer Nanodegree](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004). The Restaurant Menu project focuses on testing and improving my skills in Creating Webservers, Performing CRUD Operations, Routing, Creating API endpoints and rendering the output via HTML templates using the Flask Framework and SQLAlchemy while applying Iterative Development principles. 

## Project contents

The required files/folders for this project to run include:

* static/ - contains the necessary css files and media files.
* templates/ - contains HTML templates for pages.
* database_setup.py - Script to setup DB for our restaurants
* populate_db.py - Script to populate our Restaurant DB with dummy data
* finalproject.py - Main script that holds all the necessary information for our webserver and website to run

## Requirements
* Vagrant
* VirtualBox

## Setting up your Virtual Machine

* Step 0: 
Download and install the [VirtualBox](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1) platform package for your operating system. You do not need the extension pack or the SDK. You do not need to launch VirtualBox after installing it; Vagrant will do that. Currently (October 2017), the supported version of VirtualBox to install is version 5.1, newer versions do not work with Vagrant.

* Step 1:
Download and install the [Vagrant](https://www.vagrantup.com/downloads.html) version for your operating system. If Vagrant is successfully installed, you will be able to run `vagrant --version` in your terminal to see the version number.

* Step 2:
Duplicate the Vagrantfile (here)[https://github.com/tayomadein/fsnd-making-webservers/blob/master/Vagrantfile] in your project folder. I named my project folder `vagrant` and copied the `Vagrantfile` there. 

* Step 3:

From terminal, navigate to the `vagrant` folder and then run `vagrant up`, this will install a linux operating system in Vagrant.

* Step 4:
You can now run `vagrant ssh` to log in to your newly installed Linux VM! Follow the screen prompts

## How to run project

* Step 0:

Clone this repo to your `vagrant` root folder
```
git clone https://github.com/tayomadein/fsnd-catalog.git
```
___or___
Download this repo as a zipped file from [Github](https://github.com/tayomadein/fsnd-catalog/archive/master.zip)

* Step 1:

Fireup your app by switching into your shared folder from terminal `cd /vagrant/catalog`, then run this command

```
python app.py
``` 

* Step 2:

Open your favorite browser and go to `http://localhost:5000/` or `http://0.0.0.0:5000/`
