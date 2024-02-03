while ($True) {
    Start-Job {
        $smtpServer = "mails.tsinghua.edu.cn"
        $smtpPort = 25
        $smtpUsername = "用户名@mails.tsinghua.edu.cn"
        $smtpPassword = "应用密码"
        $from = "用户名@mails.tsinghua.edu.cn"
        $to = "收件人"
        $subject = "IP"
        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $IP = curl.exe -s --max-time 10 4.ipw.cn
        if ($IP -match '^\d+\.\d+\.\d+\.\d+$') {
            $lastIP = $IP
            $body = "$time`nLatest IP: $lastIP"
        } else {
            $body = "$time`nFailed! Last IP: $lastIP"
        }
        Send-MailMessage -SmtpServer $smtpServer -Port $smtpPort -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $smtpUsername, (ConvertTo-SecureString -String $smtpPassword -AsPlainText -Force)) -From $from -To $to -Subject $subject -Body $body
    } | Wait-Job -Timeout 20
    Start-Sleep -Seconds 40
}
