## Illumio Coding Assignment

### Testing
For testing, I created some additional rules to check edge cases, such as IP address 255.255.255.255,
or the case where all port numbers (1-65535) are allowed.  There may be some cases where the code returns incorrect results for rules with IP ranges.  For instance, given the rule `outbound,udp,1-65535,133.133.133.133-133.133.255.255`
and test case `outbound,udp,37,133.133.247.2`, the code  returns true.  Since my code parses IP addresses
into doubles, rather than checking each octet explicitly, it determines that `133.133.247.2` (parsed
into `133133247002`) is inside the range given by `133.133.133.133-133.133.255.255`, since it's between `133133133133`
and `133133255255`.  I'm not very familiar with the functionality of IP addresses, so there's a possibility that the
result is accurate, and I'm misunderstanding how the octets are read.  If this result is unintended, I could 
fix it by comparing each octet separately, rather than the entire IP address.

In summary, if `133.133.247.2` is inside the range given by `133.133.133.133-133.133.255.255`, then the program's logic
may be accurate.  If not, I would need to modify the program to check each octet individually.

The testing rules and cases are in the included `.csv` files.  The script for testing appears in `int main()` in `main.cpp`,
and simply reads test cases from the `test.csv` file.

### Algorithmic and Design Choices
To improve the speed of packet checking, I've opted to use unordered sets (hash tables) as much as possible.  This takes 
a little more space and causes some overhead costs in the initial Firewall construction.  However, the end result is that
every port number, as well as every IP address that's identified specifically in the input rules, can be validated in O(1)
time.  In my current design, three of the four packet properties (direction, protocol, and port) can be checked in O(1) time.

IP ranges require a bit more effort.  My implementation uses a priority queue (heap) for IP range rules.  Each range is
stored as a pair in the priority queue, and the queue is sorted in decreasing order by the size of the IP range (this
uses a custom comparator).  For instance, an IP range of `0.0.0.0-255.255.255.255` would be the first entry in the priority queue, whereas a range of `5.5.5.5-5.5.100.100` would appear somewhere later on.  In the worst case scenario, a packet's IP address would need to be checked against every range entry in the priority queue. This could potentially lead to slow runtimes for rejected packets, if there are many IP ranges to check.

Each unordered set has four variants, one for each combination of direction and protocol.  This ensures that allowed port
numbers for "inbound and tcp"  packets don't overlap with allowed port numbers for "inbound and udp" or "outbound and tcp"
packets, for example.  This also allows the program to check a smaller set of IP ranges, when required.

### Refinements/Optimizations
Unfortunately, C++ doesn't allow iteration over priority queues, which is why I needed to push the contents of each priority queue into a vector.  I marked this with a comment in the code that notes its inefficiency.  This could be remedied by implementing my own heap, rather than using `priority_queue`.

Due to my unfamiliarity with stringstream, I used the `string.find` function quite a bit.  I imagine that proper use of 
stringstreams would lead to increased code clarity.

There's certainly some repeated logic in the code where I copy/pasted due to time constraints, rather than building a 
standalone function.  I've also opted to keep all the code in one file, instead of creating separate files for classes
and the testing code.

My main struggle was with IP address comparisons.  I'm sure there are more effective ways of parsing IP addresses than representing them as doubles (which may have led to inaccurate results, anyway).  Here's an explanation of the ideal
way I would have implemented IP range checks, if I had more time:

1. Parse IP addresses into numbers that can be accurately compared, probably unsigned integers.
2. Combine overlapping ranges when the Firewall is constructed.  For example, combine IP ranges `0.0.0.0-1.1.3.3` and `1.1.2.2-1.1.5.5` into `0.0.0.0-1.1.5.5`.
3. Build a heap of pairs, using a vector as the base data structure.  I wouldn't sort in decreasing order based on
the size of the IP range (as in the current implementation).  Instead, I would order in ascending order based on the
window encompassed by the IP range.  For example, given IP ranges `1.1.1.1-1.1.5.5`, `0.0.0.0-0.0.4.4`, and `133.133.0.0-133.133.100.100`, my vector would look like
`[<0.0.0.0,0.0.4.4>, <1.1.1.1,1.1.5.5>, <133.133.0.0,133.133.100.100>]` (though, at this point, the IPs would be parsed into unsigned integers).
4. For validating IP addresses, I would start by checking the hash table of individual IP addresses, as in the current
implementation.  However, then I could implement a version of binary search to find a valid IP range (or lack of one) in
O(log n) time, where n is the total number of IP ranges.  For instance, given the IP address `133.133.50.50`, I would first check the middle IP range.  The IP address is not within this range, so the program would then check the latter half of my heap of IP range entries (since `133.133.50.50` is greater than the upper limit of  `1.1.1.1-1.1.5.5`).  This would be significantly quicker than my current implementation, which will, in the case of a rejected packet, check every IP range provided by the input.


#### Team Interest
I’m interested in all three teams, but I would rank the options as follows:
1.	Platform Team
2.	Data Team
3.	Policy Team 

