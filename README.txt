15441 p3-final submition

1. Usage:
./peer [-h] [-d <debug_level>] -p <peerfile> -c <chunkfile> -m <maxconn> 
-f <master-chunk-file> -i <identity> 

for example:
./peer -m 4 -p ../test/testnodes.map -f ../test/C.chunks -c ../test/B.chunks 
-i 2 

2. Timer 
We use the timeout parameter of "select" call to trigger the timer.
For each type of event that depends on a timer, we implent a special queue.
For each element, except the first, it records the left time relative to its
previous element's timeout. The first element always records the absolute time 
left before itself timeout.
For a period, we only need to check the first element (or first a few) in the 
queue, to decide whether a timeout happens. Doing this avoids iterating
through every element that have a timeout timer and improves the system
performance.

3. Scheduler
There is a scheduler to dispatch the chunks to be download. The scheduler is
triggered by some events, like timeout, one chunk download finish or ihave
packet received. 

4. Peer selection
To improve download performance, we need to download from peers in better
network condition (large bandwith, low latency ...). Such work could be 
achieved by an workaround. Peers in better network condition could often 
replay an request faster than others. Using this observation, we consider 
peer that reply the whohas request faster as one in better network condition.
We prioritize peers in better condition when scheduling download.

5. Peer down detection
We set a timer for each download or sending event. If one node doesn't get
any valid response from the interacting peer for a while, it believes the 
peer is down. For the purpose of the project, we set the time as a short
period. But in reality, the period could be much longer than we set here.

6. Test
We provide several test cases, which are in the test_case folder.
The tests.txt is also in the folder.

/****************************************************************************/
15441 p3-cp1

1. Usage:
./peer [-h] [-d <debug>] -p <peerfile> -c <chunkfile> -m <maxconn> 
-f <master-chunk-file> -i <identity>

for example:
./peer -m 4 -p ../test/testnodes.map -f ../test/C.chunks -c ../test/B.chunks 
-i 2

2. Implementation:
For check point 1, the stop and wait protocol is used and assuming the network
is reliable.


NOTE:
Please don't input when an downloading is processing. This will result the
program aborting. This will be well handled for final submission.
