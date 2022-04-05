$(document).ready(function(){
    console.log("Get Ready !")
})

$("#sendReportBtn").click(function(e){
    var email = $("#email").val()
    var filepath = 'statics/docs/' + $("#chooseReportBtn").val().slice(12)
    var filename = $("#chooseReportBtn").val().slice(12) 
    var subject = $("#Subject").val()
    e.preventDefault();
    sendEmail(email,subject,filename,filepath)
    
})

function clear(){
    console.log("Clear");
}

function sendEmail(email,subject,filename,filepath){
    $.ajax({
        type: "POST",
        url: "/report/sendmail",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            email : email,
            subject : subject,
            filename : filename,
            filepath : filepath
        }), 
        success: function(){
            console.log("success")
            window.location.replace("/report")
            alert("Sending Sucsess !!!")        
        },
        error: function(){
            console.log("Error!")
            window.location.replace("/report")            
            alert("Sending Sucsess !!!")        

        }
    });
    console.log("Button send click!")
}
