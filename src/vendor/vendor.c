/*
 *
 * Copyright (C) 2019, Broadband Forum
 * Copyright (C) 2016-2019  CommScope, Inc
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file vendor.c
 *
 * Implements the interface to all vendor implemented data model nodes
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <glob.h>

#include "usp_err_codes.h"
#include "vendor_defs.h"
#include "vendor_api.h"
#include "usp_api.h"
#include "vendor_iopsys.h"

#define ROOT_CERT_PATTERN "/etc/obuspa/*.pem"

static glob_t cert_paths;

//-----------------------------------------------------------------------------
// Vendor hook called back to obtain the trust store certificates
const trust_store_t *GetMyTrustStore(int *num_trusted_certs)
{

    int num_certs = cert_paths.gl_pathc;
    int cert_index = 0;
    char **p;
    trust_store_t *usp_agent_trust_store = (trust_store_t *)malloc(num_certs*sizeof(trust_store_t));
    for(p=cert_paths.gl_pathv; *p != NULL; ++p) {
        FILE *fp;
        fp = fopen(*p, "r");

        if(!fp)
            continue;

        X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert) {
            USP_LOG_Error("[%s:%d] Error parsing x509 cert",__func__, __LINE__);
            fclose(fp);
            continue;
        }
        unsigned char *eco_agent_root_der = NULL;
        int size = i2d_X509(cert, &eco_agent_root_der);
        if(eco_agent_root_der) {
            usp_agent_trust_store[cert_index].cert_data = eco_agent_root_der ;
            usp_agent_trust_store[cert_index].cert_len = size ;
            usp_agent_trust_store[cert_index].role = kCTrustRole_FullAccess;
            cert_index++;
        }
        fclose(fp);
        X509_free(cert);
    }
    *num_trusted_certs = cert_index;
    return usp_agent_trust_store;
}

/*********************************************************************//**
**
** VENDOR_Init
**
** Initialises this component, and registers all parameters and vendor hooks, which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Init(void)
{

    int err = USP_ERR_OK;

    err = iopsys_dm_Init();
    // Exit if any errors occurred
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("[%s:%d] Internal Error",__func__, __LINE__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Hook trust store if certificate present in path
    if ( 0 == glob(ROOT_CERT_PATTERN, 0, NULL, &cert_paths)) {
        vendor_hook_cb_t   my_core_vendor_hooks = {0};
        my_core_vendor_hooks.get_trust_store_cb  = GetMyTrustStore;
        USP_REGISTER_CoreVendorHooks(&my_core_vendor_hooks);
    }
    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}


/*********************************************************************//**
**
** VENDOR_Start
**
** Called after data model has been registered and after instance numbers have been read from the USP database
** Typically this function is used to seed the data model with instance numbers or 
** initialise internal data structures which require the data model to be running to access parameters
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Start(void)
{
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_Stop
**
** Called when stopping USP agent gracefully, to free up memory and shutdown
** any vendor processes etc
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Stop(void)
{

    return USP_ERR_OK;
}

