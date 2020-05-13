# Running multiple servers

The current setup is ready for 4 simulatenous servers, tolerating 1 fault.

First, you must delete the content of the servers Databases.

To do that, go to *dpas-server/src/database* folder and run the script:
    
    ./cleanDatabase
    
To run every server, open four new terminals in the dpas-server folder and run in each server:
    
    mvn exec:java -Dserver.id=X

With X going from 0 to N-1 servers. 

# Changing the number of tolerable faults

To change the tolerated faults, the following steps must be followed:
    
    In the file keystore.sh, change the value of the *faults* variable to the desired number. 
    This will generate 3x*faults*+1 server keys and certificates. 
    After the change, run the script by running the command ./keystore.sh in a terminal.
    
    To update the tests to run with the new number of faults, update the value in the tests constructor of the ClientLibrary class to the desired number of faults.
    It is the final argument of the constructor in line 95 of the ClientLibrary class.

With this, the change is complete!

# How to compile and test

After having all desired instances of the server running, in the project base folder, run:
    
    mvn test
    
DISCLAIMERS:
In MultiClientTest, depending of the speed of the computer, clients can finish their tests and verify the number of posted announcements before other clients have finished writing, leading to an error in this test. In our personal machines it works fine and we assume that in any other machine, as long as the failure is due to an Assertion error, the concurrency is correct.

Due to the Bizantine Quorum in the distributed alghoritms, usually one server tends to be left behind, as the Quorum only needs (for the case of 1 fault) 3 servers to answer. As such, this server will be overloaded by requests that he cannot answer yet, taking some time for him to take all updates in the correct order. So by the end of the MultiClientTest, a server usually will still be running updates, but that is fine, as we have confirmed that eventually he finishes taking in all updates necessary.

# Testing directly with client

To run the client implementation that uses the library, while the servers are on,  go to the dpas-client folder and run:

    mvn exec:java

# Manual multiple clients

Right now we have prepared for at most 3 clients running at the same time, with more able to be added by adding new certificates. 
To run each client in the dpas-client folder, with X equal to client 1, 2 or 3, run:

    mvn exec:java -Dclient.id=X

# A guide to the interface

Each client will have an associated ID defined in each client console. 
The client own ID will always be 0. To check other clients IDs, see option 1 "See registered client", which will indicate the public keys with their IDs.

To read from a Personal Board, insert the ID of the client you want to read by looking at the options from "See registered client".
