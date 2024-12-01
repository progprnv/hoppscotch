import { ref, watch } from "vue"
import { Service } from "dioc"
import { PersistenceService } from "~/services/persistence"
import {
  CACertificateEntry,
  ClientCertificateEntry,
  CACertStore,
  ClientCertsStore,
} from "./persistence"

export class NativeCertStore extends Service {
  public static readonly ID = "NATIVE_CERT_STORE"

  private readonly persistence = this.bind(PersistenceService)

  public readonly caCertificates = ref<CACertificateEntry[]>([])
  public readonly clientCertificates = ref<Map<string, ClientCertificateEntry>>(
    new Map()
  )
  public readonly validateCerts = ref(true)
  public readonly proxyUrl = ref<string>()

  override onServiceInit() {
    this.loadState()
    this.setupPersistence()
  }

  private loadState() {
    this.loadValidationConfig()
    this.loadProxyConfig()
    this.loadCACertificates()
    this.loadClientCertificates()
  }

  private loadValidationConfig() {
    const config = JSON.parse(
      this.persistence.getLocalConfig("native_interceptor_validate_ssl") ??
        "null"
    )
    if (typeof config === "boolean") this.validateCerts.value = config
  }

  private loadProxyConfig() {
    const config = this.persistence.getLocalConfig(
      "native_interceptor_proxy_info"
    )
    if (!config || config === "null") return
    try {
      const { url } = JSON.parse(config)
      this.proxyUrl.value = url
    } catch {
      this.proxyUrl.value = undefined
    }
  }

  private loadCACertificates() {
    const store = JSON.parse(
      this.persistence.getLocalConfig("native_interceptor_ca_store") ?? "null"
    )
    const result = CACertStore.safeParse(store)
    if (result.type === "ok") {
      this.caCertificates.value = result.value.certs.map((cert) => ({
        ...cert,
        certificate: new Uint8Array(cert.certificate),
      }))
    }
  }

  private loadClientCertificates() {
    const store = JSON.parse(
      this.persistence.getLocalConfig(
        "native_interceptor_client_certs_store"
      ) ?? "null"
    )
    const result = ClientCertsStore.safeParse(store)
    if (result.type === "ok") {
      this.clientCertificates.value = new Map(
        Object.entries(result.value.clientCerts).map(([domain, cert]) => [
          domain,
          this.hydrateClientCert(cert),
        ])
      )
    }
  }

  private setupPersistence() {
    watch(this.validateCerts, (value) => {
      this.persistence.setLocalConfig(
        "native_interceptor_validate_ssl",
        JSON.stringify(value)
      )
    })

    watch(this.proxyUrl, (url) => {
      this.persistence.setLocalConfig(
        "native_interceptor_proxy_info",
        url ? JSON.stringify({ url }) : "null"
      )
    })

    watch(this.caCertificates, (certs) => {
      this.persistence.setLocalConfig(
        "native_interceptor_ca_store",
        JSON.stringify({
          v: 1,
          certs: certs.map(this.dehydrateCACert),
        })
      )
    })

    watch(this.clientCertificates, (certs) => {
      this.persistence.setLocalConfig(
        "native_interceptor_client_certs_store",
        JSON.stringify({
          v: 1,
          clientCerts: Object.fromEntries(
            Array.from(certs.entries()).map(([domain, cert]) => [
              domain,
              this.dehydrateClientCert(cert),
            ])
          ),
        })
      )
    })
  }

  private hydrateClientCert(
    cert: ClientCertificateEntry
  ): ClientCertificateEntry {
    if ("PFXCert" in cert.cert) {
      return {
        ...cert,
        cert: {
          PFXCert: {
            ...cert.cert.PFXCert,
            certificate_pfx: new Uint8Array(cert.cert.PFXCert.certificate_pfx),
          },
        },
      }
    }
    return {
      ...cert,
      cert: {
        PEMCert: {
          ...cert.cert.PEMCert,
          certificate_pem: new Uint8Array(cert.cert.PEMCert.certificate_pem),
          key_pem: new Uint8Array(cert.cert.PEMCert.key_pem),
        },
      },
    }
  }

  private dehydrateCACert(cert: CACertificateEntry) {
    return {
      ...cert,
      certificate: Array.from(cert.certificate),
    }
  }

  private dehydrateClientCert(cert: ClientCertificateEntry) {
    if ("PFXCert" in cert.cert) {
      return {
        ...cert,
        cert: {
          PFXCert: {
            ...cert.cert.PFXCert,
            certificate_pfx: Array.from(cert.cert.PFXCert.certificate_pfx),
          },
        },
      }
    }
    return {
      ...cert,
      cert: {
        PEMCert: {
          ...cert.cert.PEMCert,
          certificate_pem: Array.from(cert.cert.PEMCert.certificate_pem),
          key_pem: Array.from(cert.cert.PEMCert.key_pem),
        },
      },
    }
  }
}
