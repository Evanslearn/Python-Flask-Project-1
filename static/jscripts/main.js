function disappear(myID) {
  var myID;
  var delay = 1500;

  setTimeout(myDisappear, delay, myID);
}

function myDisappear(myID) {
  var myID;
  var element = document.getElementById(myID);
  element.style.display = 'none';
}


/*
function loginForm(myID) {
    var x = document.getElementById(myID);

    if ( x.style.display === "none" ) {
        x.style.display = "block";
    }
    else {
        x.style.display = "none";
    }

}
*/

/*
function authFail(flag, myID, myMessage) {
    var flag, myID, myMessage;
    if (flag == 1) {
        document.getElementById(myID).innerHTML = myMessage;
        setTimeout(myHide, 1200, myID);
    }
    if (flag == 0) {
        document.getElementById(myID).style.display = 'none';
    }

}

function myHide(myID){
    var myID;
    const element = document.getElementById(myID);
    element.style.display = 'none';
    }

function updateText(myID) {
    var input = document.getElementByID(myID).value;
    window.alert(input);
}

*/

