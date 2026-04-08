function copyKey(elementId, button) {
    const keyElement = document.getElementById(elementId);

    if (!keyElement) {
        return;
    }

    const text = keyElement.innerText.trim();

    navigator.clipboard.writeText(text)
        .then(() => {
            const originalText = button.innerText;
            button.innerText = "Copiado!";
            button.classList.add("copied");

            setTimeout(() => {
                button.innerText = originalText;
                button.classList.remove("copied");
            }, 1500);
        })
        .catch(() => {
            const originalText = button.innerText;
            button.innerText = "Erro ao copiar";

            setTimeout(() => {
                button.innerText = originalText;
            }, 1500);
        });
}