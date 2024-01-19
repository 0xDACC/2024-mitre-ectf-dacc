*** settings ***
Library    String
Library    ../resources/serialPortReader.py
Suite Setup        Open Ports    ${SERIAL_PORT_1}
Suite Teardown     Close Ports 

*** Variables ***
${SERIAL_PORT_1}    /dev/ttyUSB0


*** test cases ***
Stop Scanning Test
    [Timeout]    30s
    # inital sleep to allow device time to boot up after programming
    sleep     5s  
    Expect And Timeout    btn 1 s\n      >>> Scanning stopped <<<    10    ${SERIAL_PORT_1}

Button Press Test
    [Timeout]    30s
    Expect And Timeout    btn 1 m\n      Medium Button 1 Press    5    ${SERIAL_PORT_1}

No button Action Test
    [Timeout]    30s
    Expect And Timeout    btn 2 s\n      No action assigned    5    ${SERIAL_PORT_1}

Clearing Bond Info Test
    [Timeout]    30s
    Expect And Timeout    btn 1 l\n      Clear bonding info    10    ${SERIAL_PORT_1}
