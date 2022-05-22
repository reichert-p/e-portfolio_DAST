# Dynamic application Security testing

# Theory

 Here are my [slides](https://docs.google.com/presentation/d/1fghEPZu9GRx1zvQ6N2t6k1PFbEIaASDiAQLjeDgWw1M/edit#slide=id.p)

# Tutorial

to start, you might follow my steps in Setup.md.

To use a supported API endpoint, choose the according endpoint from the ZAP API UI (/UI) and include it in zap.py where you want to use it.

To create a custom security check create a new script under Active Rules in the scripts tab in the ZAP UI. Implement the checks on your nodes in the scanNode() function and the checks on parameters in the scan() function.

