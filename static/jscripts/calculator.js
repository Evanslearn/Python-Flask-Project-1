// ----- ----- FUNCTIONS FOR CALCULATOR ----- -----
function writeCalc(x, myID) {
  var x, myID;
  document.getElementById(myID).value += x;

}

function clearCalc(myID) {
  document.getElementById(myID).value = "";
}

function evalCalc(myID) {
  var x, myID;
  var input, temp, output;
  input = document.getElementById(myID).value;
  /*var regplus = /[ + ]/;
  var regminus = /[ - ]/;
  var regtimes = /[ * ]/;
  var regdiv = /[ / ]/; */

  temp = splitString(input, " ");
  if (temp[1] == "+") {
    output = parseFloat(temp[0]) + parseFloat(temp[2]);
  }
  if (temp[1] == "-") {
    output = parseFloat(temp[0]) - parseFloat(temp[2]);
  }
  if (temp[1] == "*") {
    output = parseFloat(temp[0]) * parseFloat(temp[2]);
  }
  if (temp[1] == "/") {
    if ( temp[2] != 0 ) {
    output = parseFloat(temp[0]) + parseFloat(temp[2]);
    }
    else {
      output = "Do not divide by zero!";
    }
  }

  document.getElementById(myID).value = output;
}

function splitString(myString, myChar) {
  var myString, myChar;
  var newString = myString.split(myChar);
  return newString;
}

// Calculate (press =) when you press enter, as well
function Enter_Trigger(fieldID, buttonID) {
    var myval = document.getElementById(fieldID);
    myval.addEventListener("keydown", function(event) {
      if (event.keyCode === 13) {
        event.preventDefault();
        document.getElementById(buttonID).click();
      }
    });
}

