<h1 align="center" id="title">ftping</h1>

<p align="center"><img src="https://socialify.git.ci/J-bom/ftping/image?description=1&amp;language=1&amp;name=1&amp;owner=1&amp;theme=Auto" alt="project-image"></p>

<p id="description">A simple file transfer experiment using the ICMP (ping) protocol. The goal of the experiment is to transfer a file from a client to a server by hiding the file data inside an ICMP packet and sending it to the server. The server will then sniff the packet using Scapy and build the file on the server machine.</p>

  
  
<h2>🧐 Features</h2>

Here're some of the project's best features:

*   Upload files from the client to the server secretly
*   Hide information in plain sight using the ICMP protocol
*   Admire how cool this thing is

<h2>🛠️ Installation Steps:</h2>

<p>1. Clone this repo into a directory of your choosing</p>

```
git clone https://github.com/J-bom/ftping.git
```

<p>2. Change into the project's Directory</p>

```
cd ftping
```

<p>3. Install the Python package dependencies</p>

```
pip install -r requirements.txt
```

<p>4. run ftping_server.py on the server pc</p>

```
python ftping_server.py [CLIENT IP]
```

<p>5. run ftping_client.py on the client</p>

```
python ftping_client.py [SERVER IP] [LOCAL FILE PATH] [DESTINATION PATH ON THE SERVER]
```

<p>6. enjoy :)</p>

<h2>💻 Built with</h2>

Technologies used in the project:

*   Python
*   Scapy

*   A cpp based version in the future?
