// LIVE ALERTS FROM API
fetch("https://duyse17th6.execute-api.ap-south-1.amazonaws.com/prod")
    .then(res => res.json())
    .then(data => {
        document.getElementById("alertCount").innerText = data.length;

        let high = data.filter(a => a.severity === "HIGH" || a.severity === "High");
        document.getElementById("highCount").innerText = high.length;

        let table = document.getElementById("alertTable");
        data.forEach(a => {
            table.innerHTML += `
                <tr>
                    <td>${a.alert_id}</td>
                    <td>${a.attack_type}</td>
                    <td>${a.attack_type}</td>
                    <td>${a.source_ip}</td>
                </tr>
            `;
        });
    });
