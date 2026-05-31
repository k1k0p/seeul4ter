function copyKey(elementId, button) {
    /**
     * Copia o texto de um elemento específico para a área de transferência do sistema.
     * Altera visualmente o botão para indicar sucesso ou erro durante um curto período.
     * * @param {string} elementId - O ID do elemento HTML que contém o texto a ser copiado.
     * @param {HTMLElement} button - O elemento do botão que disparou a ação.
     */
    const keyElement = document.getElementById(elementId);

    if (!keyElement) {
        return;
    }

    const text = keyElement.innerText.trim();

    navigator.clipboard.writeText(text)
        .then(() => {
            /**
             * Feedback visual de sucesso: muda o texto do botão e aplica estilo CSS.
             */
            const originalText = button.innerText;
            button.innerText = "Copiado!";
            button.classList.add("copied");

            setTimeout(() => {
                button.innerText = originalText;
                button.classList.remove("copied");
            }, 1500);
        })
        .catch(() => {
            /**
             * Feedback visual de falha: informa o utilizador caso a cópia falhe.
             */
            const originalText = button.innerText;
            button.innerText = "Erro ao copiar";

            setTimeout(() => {
                button.innerText = originalText;
            }, 1500);
        });
}