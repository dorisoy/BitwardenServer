using System.Threading.Tasks;
using Bit.Core.Models.Table;
using System.Collections.Generic;
using System;

namespace Bit.Core.Services
{
    public interface IMailService
    {
        Task SendWelcomeEmailAsync(User user);
        Task SendVerifyEmailEmailAsync(string email, Guid userId, string token);
        Task SendVerifyDeleteEmailAsync(string email, Guid userId, string token);
        Task SendChangeEmailAlreadyExistsEmailAsync(string fromEmail, string toEmail);
        Task SendChangeEmailEmailAsync(string newEmailAddress, string token);
        Task SendTwoFactorEmailAsync(string email, string token);
        Task SendNoMasterPasswordHintEmailAsync(string email);
        Task SendMasterPasswordHintEmailAsync(string email, string hint);
        Task SendOrganizationInviteEmailAsync(string organizationName, OrganizationUser orgUser, string token);
        Task SendOrganizationAcceptedEmailAsync(string organizationName, string userEmail,
            IEnumerable<string> adminEmails);
        Task SendOrganizationConfirmedEmailAsync(string organizationName, string email);
        Task SendOrganizationUserRemovedForPolicyTwoStepEmailAsync(string organizationName, string email);
        Task SendPasswordlessSignInAsync(string returnUrl, string token, string email);
        Task SendInvoiceUpcomingAsync(string email, decimal amount, DateTime dueDate, List<string> items,
            bool mentionInvoices);
        Task SendPaymentFailedAsync(string email, decimal amount, bool mentionInvoices);
        Task SendAddedCreditAsync(string email, decimal amount);
        Task SendLicenseExpiredAsync(IEnumerable<string> emails, string organizationName = null);
        Task SendNewDeviceLoggedInEmail(string email, string deviceType, DateTime timestamp, string ip);
        Task SendRecoverTwoFactorEmail(string email, DateTime timestamp, string ip);
        Task SendOrganizationUserRemovedForPolicySingleOrgEmailAsync(string organizationName, string email);
        Task SendEmergencyAccessInviteEmailAsync(EmergencyAccess emergencyAccess, string name, string token);
        Task SendEmergencyAccessAcceptedEmailAsync(string granteeEmail, string email);
        Task SendEmergencyAccessConfirmedEmailAsync(string grantorName, string email);
        Task SendEmergencyAccessRecoveryInitiated(EmergencyAccess emergencyAccess, string initiatingName, string email);
        Task SendEmergencyAccessRecoveryApproved(EmergencyAccess emergencyAccess, string approvingName, string email);
        Task SendEmergencyAccessRecoveryRejected(EmergencyAccess emergencyAccess, string rejectingName, string email);
        Task SendEmergencyAccessRecoveryReminder(EmergencyAccess emergencyAccess, string initiatingName, string email);
        Task SendEmergencyAccessRecoveryTimedOut(EmergencyAccess ea, string initiatingName, string email);
    }
}
