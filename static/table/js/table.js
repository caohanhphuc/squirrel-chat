(function ($) {
	"use strict";

	$.getJSON("/channels", function(channels) {
		var tableBody = document.getElementById("table_body");
		if (Array.isArray(channels)) {
			if (channels.length > 0) {
				channels.forEach(function(channel) {
					var channel_name = channel[0];
					var channel_topic = channel[1];
					var isMember = channel[2];
					var admins = channel[3];
					var isAdmin = channel[4];
					var row = tableBody.insertRow(tableBody.rows.length-1);
					row.setAttribute("class", "row100");

					var cellOne = row.insertCell(0);
					cellOne.setAttribute("class", "column100 column1");
					cellOne.setAttribute("data-column", "column1");
					var linkOne = document.createElement("A");
					//linkOne.setAttribute("href", "/channel/" + channel_name.substring(1));
					var buttonOne = document.createElement("BUTTON");
					buttonOne.innerHTML = channel_name;
					if (isAdmin == 1){
						var star = document.createElement("IMG");
						star.setAttribute("src", "/static/channel/images/ic_star_rate_black_18dp/web/ic_star_rate_black_18dp_2x.png");
						cellOne.appendChild(star);
					}
					cellOne.appendChild(linkOne);
					linkOne.appendChild(buttonOne);

					var cellTwo = row.insertCell(1);
					cellTwo.setAttribute("class", "column100 column2");
					cellTwo.setAttribute("data-column", "column2");
					cellTwo.innerHTML = channel_topic;

					var cellFour = row.insertCell(2);
					cellFour.setAttribute("class", "column100 column4");
					cellFour.setAttribute("data-column", "column4");
					cellFour.innerHTML = admins;

					var cellThree = row.insertCell(3);
					cellThree.setAttribute("class", "column100 column3");
					cellThree.setAttribute("data-column", "column3");
					var linkThree = document.createElement("A");
					var buttonThree = document.createElement("BUTTON");
					if (isMember == 0){
						linkThree.setAttribute("href", "/join/" + channel_name.substring(1));
						buttonThree.innerHTML = "Join channel";
						linkOne.onclick = function(){
							window.alert("Need to join channel before entering channel page!");
						};
					} else {
						linkOne.setAttribute("href", "/channel/" + channel_name.substring(1));
						linkThree.setAttribute("href", "/leave/" + channel_name.substring(1));
						buttonThree.innerHTML = "Leave channel";
					}
					cellThree.appendChild(linkThree);
					linkThree.appendChild(buttonThree);
				});
			}
		}
	});


	$('.column100').on('mouseover',function(){
		var table1 = $(this).parent().parent().parent();
		var table2 = $(this).parent().parent();
		var verTable = $(table1).data('vertable')+"";
		var column = $(this).data('column') + ""; 

		$(table2).find("."+column).addClass('hov-column-'+ verTable);
		$(table1).find(".row100.head ."+column).addClass('hov-column-head-'+ verTable);
	});

	$('.column100').on('mouseout',function(){
		var table1 = $(this).parent().parent().parent();
		var table2 = $(this).parent().parent();
		var verTable = $(table1).data('vertable')+"";
		var column = $(this).data('column') + ""; 

		$(table2).find("."+column).removeClass('hov-column-'+ verTable);
		$(table1).find(".row100.head ."+column).removeClass('hov-column-head-'+ verTable);
	});

    /*==================================================================
    [ Validate 1]*/
    var input1 = $('.validate-input-1 .input100');

    $('.validate-form-1').on('submit',function(){
    	var check = true;

    	for(var i=0; i<input1.length; i++) {
    		if(validate(input1[i]) == false){
    			showValidate(input1[i]);
    			check=false;
    		}
    	}

    	return check;
    });


    $('.validate-form-1 .input100').each(function(){
    	$(this).focus(function(){
    		hideValidate(this);
    	});
    });

    /*==================================================================
    [ Validate ]*/
    var input2 = $('.validate-input-2 .input100');

    $('.validate-form-2').on('submit',function(){
    	var check = true;

    	for(var i=0; i<input2.length; i++) {
    		if(validate(input2[i]) == false){
    			showValidate(input2[i]);
    			check=false;
    		}
    	}

    	return check;
    });


    $('.validate-form-2 .input100').each(function(){
    	$(this).focus(function(){
    		hideValidate(this);
    	});
    });

    /*================================================================== */

    function validate (input) {
    	if($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
    		if($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
    			return false;
    		}
    	}
    	else {
    		if($(input).val().trim() == ''){
    			return false;
    		}
    	}
    }

    function showValidate(input) {
    	var thisAlert = $(input).parent();

    	$(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
    	var thisAlert = $(input).parent();

    	$(thisAlert).removeClass('alert-validate');
    }


})(jQuery);

function closeChannelModal(){
	var channelModal = document.getElementById('channelModal');
	channelModal.style.display = "none";
};

function closeBlockModal(){
	var blockModal = document.getElementById('blockModal');
	blockModal.style.display = "none";
};

document.getElementById('channelModal').style.display = "none";
document.getElementById('blockModal').style.display = "none";

var channelModal = document.getElementById('channelModal');
var blockModal = document.getElementById('blockModal');

var channelBtn = document.getElementById("add_chan_btn");
var blockUserBtn = document.getElementById("block_user_btn");

channelBtn.onclick = function() {
    channelModal.style.display = "block";
};

blockUserBtn.onclick = function() {
    blockModal.style.display = "block";
};