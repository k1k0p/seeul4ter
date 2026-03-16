document.addEventListener("DOMContentLoaded", () => {
    const fileInputs = document.querySelectorAll('input[type="file"]');

    fileInputs.forEach((input) => {
        input.addEventListener("change", () => {
            if (input.files.length > 0) {
                console.log("Ficheiro selecionado:", input.files[0].name);
            }
        });
    });
});