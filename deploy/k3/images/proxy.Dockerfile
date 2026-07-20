FROM mitmproxy/mitmproxy:11.0.2
COPY deploy/k3/proxy/addon.py /opt/open-swe/addon.py
EXPOSE 8080 8081
ENTRYPOINT ["mitmdump"]
CMD ["--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "block_global=false", "--set", "console_eventlog_verbosity=warn", "-s", "/opt/open-swe/addon.py"]
