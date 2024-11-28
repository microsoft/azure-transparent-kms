// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//import { ccf } from "@microsoft/ccf-app/global";
import { DemoMemberProps, DemoProps } from "./index";
import axios from "axios";
import {
  IHeartbeatResponse,
  IKeyItem,
  IKeyReleasePolicySnpProps,
  ITinkPublicKeySet,
} from "../../../src";
import https from "https";
import * as http2 from "http2";

export interface ValidationProps {
  url: string;
  method: "POST";
  member: DemoMemberProps;
  expectedStatus: number;
  testMessage: string;
}

export const convertUint8ArrayToString = (uInt8array: Uint8Array): string => {
  let stringRepresentation = "";
  for (let i = 0; i < uInt8array.length; i++) {
    stringRepresentation += String.fromCharCode(uInt8array[i]);
  }
  return stringRepresentation;
};
export class Validator {
  public static async validateRequest(props: ValidationProps) {
    const result = await axios({
      method: props.method,
      url: props.url,
      data: props.member.data,
      validateStatus: function (status) {
        return status < 500; // Resolve only if the status code is less than 500
      },
    });

    if (result.status !== props.expectedStatus) {
      throw new Error(
        `🛑 [TEST FAILURE]: ${props.member.name} - ${props.testMessage}: ${props.expectedStatus} expected, but got ${result.status}.`,
      );
    }

    console.log(`✅ [PASS] ${props.member.name} - ${props.testMessage}`);
  }
}

export default class Api {
  private static responsePromise(
    request: http2.ClientHttp2Stream,
    responseType = "json",
  ) {
    return new Promise((resolve, reject) => {
      let data: string = "";
      let chunks: Buffer[] = [];
      let statusCode = 0;
      let headers: http2.IncomingHttpHeaders = {};

      request.on("data", (chunk: string | Buffer) => {
        if (responseType === "json") {
          data += chunk;
        } else {
          chunks.push(chunk as Buffer);
        }
      });

      request.on("end", () => {
        if (responseType === "json") {
          resolve({ statusCode, data, headers });
        } else {
          let data = Buffer.concat(chunks);
          resolve({ statusCode, data, headers });
        }
      });

      request.on("response", (responseHeaders) => {
        headers = responseHeaders;
        const statusHeader = headers[":status"];
        statusCode = Array.isArray(statusHeader)
          ? parseInt(statusHeader[0])
          : parseInt(statusHeader || "0");
      });
      request.on("error", (error) => {
        reject(error);
      });
    });
  }

  public static async heartbeat(
    props: DemoProps,
    member: DemoMemberProps,
    httpsAgent: https.Agent,
    authorizationHeader?: string,
  ): Promise<[number, IHeartbeatResponse]> {
    console.log(`heartbeat authorization header: ${authorizationHeader}`);

    const reqProps: http2.OutgoingHttpHeaders = authorizationHeader
      ? {
          ":method": "GET",
          ":path": `${props.heartbeatPath}`,
          "Content-Type": "application/json",
          Authorization: authorizationHeader,
        }
      : {
          ":method": "GET",
          ":path": `${props.heartbeatPath}`,
          "Content-Type": "application/json",
        };

    const client = http2.connect(props.url, {
      ...httpsAgent.options,
      rejectUnauthorized: true,
    } as http2.SecureClientSessionOptions);
    const req = client.request(reqProps);
    req.end();

    let response;
    try {
      response = await Api.responsePromise(req);
      console.log("Status:", response.statusCode);
      console.log("Response data:", response.data);
    } catch (error: any) {
      console.error("Error:", error.message);
    } finally {
      // Close the client session when done
      if (client) {
        client.close();
      }
    }
    return [response.statusCode, JSON.parse(response.data)];
  }

  public static async refresh(
    props: DemoProps,
    member: DemoMemberProps,
    httpsAgent: https.Agent,
    authorizationHeader?: string,
  ): Promise<[number, IKeyItem]> {
    console.log(`Refresh props:`, props);
    console.log(`Refresh https agent:`, httpsAgent);
    console.log(`Refresh authorization header:`, authorizationHeader);
    console.log(`${member.name} Refresh key:`);
    const reqProps: http2.OutgoingHttpHeaders = authorizationHeader
      ? {
          ":method": "POST",
          ":path": `${props.refreshPath}`,
          "Content-Type": "application/json",
          Authorization: authorizationHeader,
        }
      : {
          ":method": "POST",
          ":path": `${props.refreshPath}`,
          "Content-Type": "application/json",
        };
    const client = http2.connect(props.url, {
      ...httpsAgent.options,
      rejectUnauthorized: true,
    } as http2.SecureClientSessionOptions);
    const req = client.request(reqProps);

    req.end();

    let response;
    try {
      response = await Api.responsePromise(req);
      console.log("Status:", response.statusCode);
      console.log("Response data:", response.data);
    } catch (error: any) {
      console.error("Error:", error.message);
    } finally {
      // Close the client session when done
      if (client) {
        client.close();
      }
    }
    return [response.statusCode, JSON.parse(response.data)];
  }

  public static async key(
    props: DemoProps,
    member: DemoMemberProps,
    privateWrapKey: string,
    publicWrapKey: string,
    kid: string | undefined,
    httpsAgent: https.Agent,
    authorizationHeader?: string,
  ): Promise<IKeyResponse>
 {
    console.log(
      `${member.name} Get wrapped private key with receipt. tink: ${tink}:`,
      authorizationHeader,
    );
    let query = "";
    if (kid) {
      if (query === "") {
        query = `?kid=${kid}`;
      } else query = `${query}&kid=${kid}`;
    }
    const reqProps: http2.OutgoingHttpHeaders = authorizationHeader
      ? {
          ":method": "POST",
          ":path": `${props.keyPath}${query}`,
          "Content-Type": "application/json",
          Authorization: authorizationHeader,
        }
      : {
          ":method": "POST",
          ":path": `${props.keyPath}${query}`,
          "Content-Type": "application/json",
        };
    const client = http2.connect(props.url, {
      ...httpsAgent.options,
      rejectUnauthorized: true,
    } as http2.SecureClientSessionOptions);
    const req = client.request(reqProps);
    req.write(JSON.stringify({ attestation, wrappingKey: publicWrapKey }));
    req.end();

    let response;
    try {
      response = await Api.responsePromise(req);
      console.log("Status:", response.statusCode);
      if (response.statusCode > 200) {
        console.log(
          `Directly return statuscode with response (${response.statusCode}): `,
          response.data,
        );
        return [
          response.headers,
          response.statusCode,
          response.data ? JSON.parse(response.data) : undefined,
        ];
      }
      console.log("Response data:", response.data);
    } catch (error: any) {
      console.error("Error:", error.message);
    } finally {
      // Close the client session when done
      if (client) {
        client.close();
      }
    }

      const resp = JSON.parse(response.data);
      console.log(`key returned: `, response.data);
      const receipt = resp.receipt;
      console.log(`wrappedKid: `, resp.wrappedKid);
      console.log(`Receipt: `, resp.receipt);

      return [
        response.headers,
        response.statusCode,
        {
          receipt,
          wrapped: resp.wrapped,
          wrappedKid: resp.wrappedKid,
        },
      ];
  }

  public static async keyReleasePolicy(
    props: DemoProps,
    member: DemoMemberProps,
    httpsAgent: https.Agent,
    authorizationHeader?: string,
  ): Promise<
    [number, IKeyReleasePolicySnpProps, { [key: string]: string | number }]
  > {
    console.log(`${member.name} Get key release policy`);
    console.log(`Get key release policy props:`, props);
    console.log(`Get key release policy https agent:`, httpsAgent);
    console.log(
      `Get key release policy authorization header:`,
      authorizationHeader,
    );
    const reqProps: http2.OutgoingHttpHeaders = authorizationHeader
      ? {
          ":method": "GET",
          ":path": `${props.keyReleasePolicyPath}`,
          "Content-Type": "application/json",
          Authorization: authorizationHeader,
        }
      : {
          ":method": "GET",
          ":path": `${props.keyReleasePolicyPath}`,
          "Content-Type": "application/json",
        };
    const client = http2.connect(props.url, {
      ...httpsAgent.options,
      rejectUnauthorized: true,
    } as http2.SecureClientSessionOptions);
    const req = client.request(reqProps);

    req.end();

    let response;
    try {
      response = await Api.responsePromise(req);
      console.log("Status:", response.statusCode);
      console.log("Response data:", response.data);
    } catch (error: any) {
      console.error("Error:", error.message);
    } finally {
      // Close the client session when done
      if (client) {
        client.close();
      }
    }
    return [
      response.statusCode,
      <IKeyReleasePolicySnpProps>JSON.parse(response.data),
      response.headers,
    ];
  }

  public static async listpubkeys(
    props: DemoProps,
    member: DemoMemberProps,
    httpsAgent: https.Agent,
    authorizationHeader?: string,
  ): Promise<IPublicKey[]> {
    console.log(`${member.name} Get listpubkeys`);
    console.log(`Get listpubkeys props:`, props);
    console.log(`Get listpubkeys https agent:`, httpsAgent);
    console.log(`Get listpubkeys authorization header:`, authorizationHeader);
    const reqProps: http2.OutgoingHttpHeaders = authorizationHeader
      ? {
          ":method": "GET",
          ":path": `${props.listpubkeysPath}`,
          "Content-Type": "application/json",
          Authorization: authorizationHeader,
        }
      : {
          ":method": "GET",
          ":path": `${props.listpubkeysPath}`,
          "Content-Type": "application/json",
        };
    const client = http2.connect(props.url, {
      ...httpsAgent.options,
      rejectUnauthorized: true,
    } as http2.SecureClientSessionOptions);
    const req = client.request(reqProps);

    req.end();

    let response;
    try {
      response = await Api.responsePromise(req);
      console.log("Status:", response.statusCode);
      console.log("Response data:", response.data);
      console.log("Response headers:", response.headers);
    } catch (error: any) {
      console.error("Error:", error.message);
    } finally {
      // Close the client session when done
      if (client) {
        client.close();
      }
    }
    return [
      response.statusCode,
      <ITinkPublicKeySet>JSON.parse(response.data),
      response.headers,
    ];
  }
}