**#Description**
  This repository is a Locust script for the JFrog assignment API scenario. The script has been written using python language and uses Locust. 
  This project utilizes docker to execute performance test.

**Prerequisite:**
  1. Docker desktop is Installed
  2. Python is Installed
  3. IDE of your choice is Installed (Used IDE: pycharm)

**Steps :**
  1. Import this project into pycharm (IDE of your choice) & create a Virtual Environment to be used
  2. Install Locust in the Virtual Environment
     Command : pip install locust
  3. Verify Locust by running "locust --version"

**Execution**
  Command : **$env:UserCount="1"; $env:UserRate="1"; $env:Duration="30m";$env:HostUrl="https://trials6p3nw.jfrog.io/"; docker-compose up --build**

**Explanation**
    UserCount : Total User load for the performance test
    UserRate : User arrival rate per second
    Duration : Total Test duration (e.g. For 30 Minute : 30m, For 30 Seconds : 30s)
    HostUrl : Application URL
