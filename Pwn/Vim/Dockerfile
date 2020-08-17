FROM ubuntu:18.04

RUN apt-get update

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
 
WORKDIR /home/ctf
COPY ./distribute/vim .
COPY flag .
COPY ynetd .
COPY ./distribute/run.sh .


RUN chown -R root:root /home/ctf/

USER ctf
CMD ./run.sh

