import { Service } from "dioc"
import { NativeInterceptor } from "~/kernel/native"
import { Request, CertificateType } from "@hoppscotch/kernel"
import { KernelInterceptor } from "~/services/kernel-interceptor.service"
import { CookieJarService } from "~/services/cookie-jar.service"
import { NativeCertStore } from "./cert-store"
import SettingsNativeInterceptor from "~/components/settings/NativeInterceptor.vue"

export class NativeKernelInterceptorService
  extends Service
  implements KernelInterceptor
{
  public static readonly ID = "NATIVE_KERNEL_INTERCEPTOR_SERVICE"

  private readonly cookieJar = this.bind(CookieJarService)
  private readonly certStore = this.bind(NativeCertStore)

  public readonly id = "native"
  public readonly name = () => "Native"
  public readonly selectable = { type: "selectable" as const }

  public readonly settingsEntry = {
    title: () => "Native",
    component: SettingsNativeInterceptor,
  }

  public execute(req: Request) {
    const requestWithCookies = this.attachCookies(req)
    const requestWithCerts = this.attachCertificates(requestWithCookies)

    return NativeInterceptor.execute(requestWithCerts)
  }

  private attachCookies(req: Request): Request {
    const cookies = this.cookieJar.getCookiesForURL(new URL(req.url))
    if (cookies.length === 0) return req

    return {
      ...req,
      headers: {
        ...req.headers,
        Cookie: cookies
          .map((cookie) => `${cookie.name!}=${cookie.value!}`)
          .join(";"),
      },
    }
  }

  private attachCertificates(req: Request): Request {
    const url = new URL(req.url)
    const clientCert = this.getClientCertForDomain(url.host)

    return {
      ...req,
      security: {
        certificates: {
          ca: this.certStore.caCertificates.value
            .filter((cert) => cert.enabled)
            .map((cert) => cert.certificate),
          client: clientCert,
        },
        validateCertificates: this.certStore.validateCerts.value,
        verifyHost: true,
      },
      proxy: this.certStore.proxyUrl.value
        ? { url: this.certStore.proxyUrl.value }
        : undefined,
    }
  }

  private getClientCertForDomain(domain: string): CertificateType | undefined {
    const cert = this.certStore.clientCertificates.value.get(domain)
    return cert?.enabled ? cert.cert : undefined
  }
}
