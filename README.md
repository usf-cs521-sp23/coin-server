# coin-server

This is "coin-server" for all the classmates in CS521 can mine for COIN521:)))        
      
## Concept      
    
When the client already connect to the server, the client will request for the task first.   
After that, server will create the task and send it back to client.       
Then, the client can work on "mining" and get the solution then send it back to server.     
Server will verify the solution is correct or not and send the bool back to client.      
If the verification is True, client can mine again!!!        

## Steps
  

client --> request for task --> server    
server --> give the task --> client        

client working on it!!!        
 
  
client --> send solutioin --> server    
server do verify      
server --> send verification --> client     



## Build

To compile:   

make    

Usage:   
   
./coin-server port [-s seed] [-a adjective_file] [-n animal_file] [-l log_file]     
Options:     
    * -s    Specify the seed number       
    * -a    Specify the adjective file to be used       
    * -n    Specify the animal file to be used       
    * -l    Specify the log file to be used      
    
client:

./client localhost port

## Running + Example Usage


![example](https://github.com/weicheng112/coin-server/assets/108167692/dbaf71ab-e129-44ae-99f0-5d02ed344a58)  
This picture shows that our client request for the task and start working on it.    
After that, client will send the solution to the server.   
![example2](https://github.com/weicheng112/coin-server/assets/108167692/dd146ae1-8fe8-4abb-90c4-7c625812da21)    
This shows that server got the request from the client.   
Then, send the task to client immediately.    
After server got the solution sent by client. It will do verification. And send it back to that client    



