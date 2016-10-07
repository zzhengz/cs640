```
./switchyard/srpy.py -t -s test_std.py myswitch_std.py	
```
#should pass
```
./switchyard/srpy.py -t -s test_hub.py myhub.py
```
#should pass

```
./switchyard/srpy.py -t -s test_to.py myswitch_to.py
```
#should pass






all others should fail, like

```
./switchyard/srpy.py -t -s test_to.py myswitch_std.py
```
#should fail


etc
