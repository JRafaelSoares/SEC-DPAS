# How to compile and test

First, in the base folder of the project, run:
    
    mvn clean install -DskipTests
    
Then, open a new terminal (while keeping the previous one open), go to the dpas-server folder and run:

    mvn exec:java
    
This will create a DPASServer instance. To test the server, in the first terminal, run:

    mvn test

DISCLAIMER:
In MultiClientTest, depending of the speed of the computer, clients can finish their tests and verify the number of posted announcements before other clients have finished writing, leading to an error in this test. In our personal machines it works fine and we assume that in any other machine, as long as the failure is due to an Assertion error, the concurrency is correct.

# Testing directly with client

To run the client implementation that uses the library, while the server is on,  go to the dpas-client folder and run:

    mvn exec:java

# Manual multiple clients

Right now we have prepared for at most 3 clients running at the same time, with more able to be added by adding new certificates. 
To run each client in the dpas-client folder, with X equal to client 1, 2 or 3, run:

mvn exec:java -DkeyStore.alias=clientKeyPairX

# A guide to the interface

Each client will have an associated ID defined in each client console. 
The client own ID will always be 0. To check other clients IDs, see option 1 "See registered client", which will indicate the public keys with their IDs.

To read from a Personal Board, insert the ID of the client you want to read by looking at the options from "See registered client".
