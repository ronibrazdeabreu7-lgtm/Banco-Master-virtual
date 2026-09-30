document.addEventListener("DOMContentLoaded", () => {
    const messages = document.querySelectorAll(".message");

    messages.forEach((message) => {
        setTimeout(() => {
            message.style.opacity = "0";
            message.style.transition = "opacity .5s";

            setTimeout(() => {
                message.remove();
            }, 500);
        }, 6000);
    });
});
