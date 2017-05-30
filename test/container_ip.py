import sys
import json


if __name__ == '__main__':

    network = json.load(sys.stdin)
    intf = sys.argv[1]
    print network[0]['NetworkSettings']['Networks'][intf]['IPAddress']

