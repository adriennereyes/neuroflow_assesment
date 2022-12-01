# Neuroflow Assesment

## Create and activate vitrual envrionment
1. Creating virtual environment
    * ```python3 -m venv venv```
<br>

2. Activating virtual environment
   * On Windows, run:
   ```venv\Scripts\activate.bat```
    * On Unix or MacOS, run:
   ```source ./venv/bin/activate```

---

## Install dependencies
```pip3 install -r requirements.txt```

---

## Running and Using/Testing Application
Open a terminal and run api.py (the application will be run on localhost:8000):
<br>
```python3 api.py```
<br>

***I recommend using Postman to use/test the application***
<br>
Testing:
1. Open Postman application
2. Click the Collections tab on the Scratch Pad
3. Click the Import button to import a Collection
4. Select the json file I provided in root folder of this project called "Mood API.postman_collection.json"
5. Once imported it should have displayed the Mood API collection with GET and POST requests
6. For each HTTP request I provided an example of what the request headers and body should be and what response to get back<br>
these examples can displayed by toggling the drop down for each request.
7. The HTTP requests are sequentially ordered, so send the HTTP requests in that order.
8. For the POST request to login a user at localhost:8000/login it will return an authentication token. Copy the token's value to be<br>
used for the endpoints that require authentication which is the /mood endpoint both for GET and POST requests. For the GET and POST<br>
requests for the /mood endpoint add a key-value to the headers, with the key being "x-access-tokens" and value being the token to be able to send the HTTP request.
<br>

*** ***There are already records stored in the database file*** ***

---

## Production Application Scenario
If this REST API was used for production I would use different technologies in order to handle user scalability, application performance, and application security.
The technologies I would use instead to achieve this would consist of Django(Utilizing the Django Rest framework), MySQL, and Redis.
Django and its Django Rest framework is known for its simplicity, speed, reliability, and flexibility. Therefore, it can easily be adapted to any project and used to build high-load websites with huge traffic. With the use of MySQL and MySQL Cluster it will be able to handle more users and data because of its linear scalabilty and high availability. Also, MySQL is known to be secure and dependable when it comes to data protection. Next, Redis will help with performance since it will be able to cache data that we know is mostly used or not updated frequently to limit having to query data from our database. Security wise, I would implement serialization and deserialzation when sending and recieving data.
