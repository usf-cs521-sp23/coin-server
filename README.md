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
-------------------    
client working on it!!!        
-------------------    
  
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


## Running + Example Usage


![example](https://github.com/weicheng112/coin-server/assets/108167692/dbaf71ab-e129-44ae-99f0-5d02ed344a58)
![example2](https://github.com/weicheng112/coin-server/assets/108167692/dd146ae1-8fe8-4abb-90c4-7c625812da21)


