# rqlmap

RQLMAP checks Time base sql injection by changing the parametere value
and changing the header value.

## Installation
To install this Tool please use the following Command:
```
go install github.com/Ractiurd/rqlmap@latest
```


## Usage
To run this script use the following command:

For multiple url
```
cat urls.txt | rqlmap
```

For single url
```
echo "url" | rqlmap
```

## Help for rqlmap
```
  -f  >Payload file location
```
```
  -p  >SQL  payload (default "XOR(if(now()=sysdate(),sleep(10),0))XOR")
```
```
  -pr  >Set the proxy location recommended http://127.0.0.1:8080
```
```
  -t  >Set time for sql injection to get triaged  (default 10)
```


## Question
If you have an question you can create an Issue or ping me on [Ractiurd](https://twitter.com/ractiurd)
