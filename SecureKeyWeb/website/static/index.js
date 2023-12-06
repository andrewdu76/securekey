function deleteNote(noteid){
    fetch("delete-note", {
        method: "POST",
        boby: JSON.stringify({noteId: noteId}),
    
    }).then((_res) => {
        window.location.href = "/";
    });
}