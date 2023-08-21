const item = document.querySelectorAll(".item");

const sender = document.querySelector(".container");
const receiver = document.querySelector(".receiver");

item.forEach((n) => {
  n.addEventListener("click", (e) => {
    let active = e.target.textContent;

    if (active === "Sender") {
      receiver.classList.add("hide");
      sender.classList.remove("hide");
    } else {
      receiver.classList.remove("hide");
      sender.classList.add("hide");
    }
  });
});
