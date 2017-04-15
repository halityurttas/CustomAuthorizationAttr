using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace CustomAuthorizationAttr.Components
{
    public class SessionAuthorizationAttribute: System.Web.Mvc.AuthorizeAttribute
    {
        public string OkValue { get; set; }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            if (!SkipAuthorization(filterContext) && (
                    filterContext.HttpContext.Session["login"] == null || 
                    filterContext.HttpContext.Session["login"].ToString() != OkValue)
                )
            {
                filterContext.HttpContext.Response.Clear();
                filterContext.HttpContext.Response.StatusCode = 403;
                filterContext.HttpContext.Response.End();
            }
        }

        private bool SkipAuthorization(AuthorizationContext filterContext)
        {
            return filterContext.ActionDescriptor.GetCustomAttributes(
                    typeof(AllowAnonymousAttribute), true).Any();
        }
    }
}