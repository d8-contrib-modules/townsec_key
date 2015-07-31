<?php
/**
 * @file
 * Contains Drupal\key\KeyType\TownSecKey.
 *
 * Plugin definition for a key provider using
 * Townsend Security’s Alliance Key Manager service.
 */

namespace Drupal\townsec_key\Plugin\KeyType;
use Drupal\Core\Form\FormStateInterface;
use Drupal\key\KeyTypeBase;

/**
 * Enforces a number of a type of character in passwords.
 *
 * @KeyType(
 *   id = "townsec_akm",
 *   title = @Translation("Townsend Security’s Alliance Key Manager"),
 *   description = @Translation("Key provider using Townsend Security’s Alliance Key Manager service."),
 * )
 */
class TownSecKey extends KeyTypeBase {
  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'primary_server' => [
        'client_cert_and_key_file' => '',
        'ca_cert_file' => '',
        'akm_host_server' => '',
        'akm_retrieve_port' => '',
        'akm_encrypt_port' => '',
      ],
      'backup_server' => [
        'client_cert_and_key_file' => '',
        'ca_cert_file' => '',
        'akm_backup_server' => '',
        'akm_retrieve_port' => '',
        'akm_encrypt_port' => '',
      ],
      'key_name' => '',
      'key_type' => 'AES-256',
      'key_size' => '',
      'encode' => 'B64',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form['primary_server'] = array(
      '#type' => 'fieldset',
      '#title' => t('Primary Server Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );
    $form['backup_server'] = array(
      '#type' => 'fieldset',
      '#title' => t('Backup Server Settings'),
      '#collapsible' => TRUE,
      '#collapsed' => TRUE,
    );
    $form['primary_server']['client_cert_and_key_file'] = array(
      '#type' => 'textfield',
      '#title' => t('Location of Client X509 Certificate and Private Key File'),
      '#description' => t('The file location relative to the root Drupal directory (e.g. %rel).', array(
        '%rel' => '../private/cert/local.pem',
      )),
      '#default_value' => $this->configuration['primary_server']['client_cert_and_key_file'],
      '#required' => TRUE,
    );
    $form['primary_server']['ca_cert_file'] = array(
      '#type' => 'textfield',
      '#title' => t('Location of Certificate Authority Certificate File'),
      '#description' => t('The file location relative to the root Drupal directory (e.g. %rel).', array(
        '%rel' => '../private/cert/ca.pem',
      )),
      '#default_value' => $this->configuration['primary_server']['ca_cert_file'],
      '#required' => TRUE,
    );
    $form['backup_server']['client_cert_and_key_file'] = array(
      '#type' => 'textfield',
      '#title' => t('Location of Client X509 Certificate and Private Key File'),
      '#description' => t('The file location relative to the root Drupal directory (e.g. %rel).', array(
        '%rel' => '../private/cert/local.pem',
      )),
      '#default_value' => $this->configuration['backup_server']['client_cert_and_key_file'],
      '#required' => FALSE,
    );
    $form['backup_server']['ca_cert_file'] = array(
      '#type' => 'textfield',
      '#title' => t('Location of Certificate Authority Certificate File'),
      '#description' => t('The file location relative to the root Drupal directory (e.g. %rel).', array(
        '%rel' => '../private/cert/ca.pem',
      )),
      '#default_value' => $this->configuration['backup_server']['ca_cert_file'],
      '#required' => FALSE,
    );
    $form['primary_server']['akm_host_server'] = array(
      '#type' => 'textfield',
      '#title' => t('AKM Host Server'),
      '#description' => t('Enter the AKM host server name or IP number.'),
      '#default_value' => $this->configuration['primary_server']['akm_host_server'],
      '#required' => TRUE,
    );
    $form['backup_server']['akm_backup_server'] = array(
      '#type' => 'textfield',
      '#title' => t('AKM Backup Server'),
      '#description' => t('Enter the AKM Backup server name or IP number.'),
      '#default_value' => $this->configuration['backup_server']['akm_backup_server'],
      '#required' => FALSE,
    );
    $form['primary_server']['akm_retrieve_port'] = array(
      '#type' => 'textfield',
      '#title' => t('Key Retrieval Port'),
      '#description' => t('Enter the number of the port for key retrieval.'),
      '#default_value' => $this->configuration['primary_server']['akm_retrieve_port'],
      '#required' => TRUE,
    );
    $form['backup_server']['akm_retrieve_port'] = array(
      '#type' => 'textfield',
      '#title' => t('Key Retrieval Port'),
      '#description' => t('Enter the number of the port for key retrieval.'),
      '#default_value' => $this->configuration['backup_server']['akm_retrieve_port'],
      '#required' => FALSE,
    );
    $form['primary_server']['akm_encrypt_port'] = array(
      '#type' => 'textfield',
      '#title' => t('Remote Encryption Port'),
      '#description' => t('Enter the number of the port for remote encryption.'),
      '#default_value' => $this->configuration['primary_server']['akm_encrypt_port'],
      '#required' => TRUE,
    );
    $form['backup_server']['akm_encrypt_port'] = array(
      '#type' => 'textfield',
      '#title' => t('Remote Encryption Port'),
      '#description' => t('Enter the number of the port for remote encryption.'),
      '#default_value' => $this->configuration['backup_server']['akm_encrypt_port'],
      '#required' => FALSE,
    );
    $form['key_name'] = array(
      '#type' => 'textfield',
      '#title' => t('Key Name'),
      '#description' => t('Enter the name of the key.'),
      '#default_value' => $this->configuration['key_name'],
      '#required' => TRUE,
    );
    $form['key_type'] = array(
      '#type' => 'select',
      '#title' => t('Key Type'),
      '#description' => t('Choose the type of key.'),
      '#options' => array(
        'AES-256' => t('AES-256'),
      ),
      '#default_value' => $this->configuration['key_type'],
    );
    $form['key_size'] = array(
      '#type' => 'textfield',
      '#title' => t('Key Size'),
      '#description' => t('Enter the size of the key.'),
      '#default_value' => $this->configuration['key_size'],
      '#required' => TRUE,
    );
    $form['encode'] = array(
      '#type' => 'select',
      '#title' => t('Encoding Method'),
      '#description' => t('Choose the encoding method.'),
      '#options' => array(
        'BIN' => t('Binary'),
        'B64' => t('Base64 Encoded'),
        'B16' => t('Base16 Encoded'),
      ),
      '#default_value' => $this->configuration['encode'],
    );
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $this->configuration['primary_server']['client_cert_and_key_file'] = $form_state->getValue('primary_server')['client_cert_and_key_file'];
    $this->configuration['primary_server']['ca_cert_file'] = $form_state->getValue('primary_server')['ca_cert_file'];
    $this->configuration['primary_server']['akm_host_server'] = $form_state->getValue('primary_server')['akm_host_server'];
    $this->configuration['primary_server']['akm_retrieve_port'] = $form_state->getValue('primary_server')['akm_retrieve_port'];
    $this->configuration['primary_server']['akm_encrypt_port'] = $form_state->getValue('primary_server')['akm_encrypt_port'];
    $this->configuration['backup_server']['client_cert_and_key_file'] = $form_state->getValue('backup_server')['client_cert_and_key_file'];
    $this->configuration['backup_server']['ca_cert_file'] = $form_state->getValue('backup_server')['ca_cert_file'];
    $this->configuration['backup_server']['akm_backup_server'] = $form_state->getValue('backup_server')['akm_backup_server'];
    $this->configuration['backup_server']['akm_retrieve_port'] = $form_state->getValue('backup_server')['akm_retrieve_port'];
    $this->configuration['backup_server']['akm_encrypt_port'] = $form_state->getValue('backup_server')['akm_encrypt_port'];
    $this->configuration['key_name'] = $form_state->getValue('key_name');
    $this->configuration['key_type'] = $form_state->getValue('key_type');
    $this->configuration['key_size'] = $form_state->getValue('key_size');
    $this->configuration['encode'] = $form_state->getValue('encode');
  }

  /**
   * {@inheritdoc}
   */
  public function getKeyValue() {
    // If the encryption method is Townsend Security AES, don't retrieve the key.
    $encryption_method = \Drupal::config('encrypt.settings')->get('encryption_method');

    if ($encryption_method == 'townsec_aes') {
      return $this->configuration;
    }

    $primretrieve = $this->configuration['primary_server']['akm_retrieve_port'];
    $bkupretrieve = $this->configuration['backup_server']['akm_retrieve_port'];
    $primserver = 'tls://' . $this->configuration['primary_server']['akm_host_server'] . ':' . $primretrieve;
    $bkupserver = 'tls://' . $this->configuration['backup_server']['akm_backup_server'] . ':' . $bkupretrieve;
    $keyname = $this->configuration['key_name'];
    $errno = NULL;
    $errstr = NULL;
    $encode = $this->configuration['encode'];
    $primlocal = \Drupal::root() . '/' . $this->configuration['primary_server']['client_cert_and_key_file'];
    $primca = \Drupal::root() . '/' . $this->configuration['primary_server']['ca_cert_file'];
    $bkuplocal = \Drupal::root() . '/' . $this->configuration['backup_server']['client_cert_and_key_file'];
    $bkupca = \Drupal::root() . '/' . $this->configuration['backup_server']['ca_cert_file'];
    // Create TLS Connection with provided key locations.
    $primopts = array(
      'ssl' => array(
        'cafile' => $primca,
        'capture_peer_cert' => TRUE,
        'local_cert' => $primlocal,
        'verify_peer' => TRUE,
      ),
    );
    $bkupopts = array(
      'ssl' => array(
        'cafile' => $bkupca,
        'capture_peer_cert' => TRUE,
        'local_cert' => $bkuplocal,
        'verify_peer' => TRUE,
      ),
    );
    // Create TLS context.
    $primctx = stream_context_create($primopts);
    $bkupctx = stream_context_create($bkupopts);
    // Request Key.
    if ($fp = stream_socket_client($primserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $primctx)) {
      $request = sprintf("000712001%-40s%24s" . $encode, $keyname, '');
      fwrite($fp, $request);
      $len = fread($fp, 5);
      if ($len) {
        $rsp = fread($fp, $len + 1);
        if ($rsp) {
          $key = substr($rsp, 95);
        }
      }
      fclose($fp);
    }
    elseif ($fp = stream_socket_client($bkupserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $bkupctx)) {
      $request = sprintf("000712001%-40s%24s" . $encode, $keyname, '');
      fwrite($fp, $request);
      $len = fread($fp, 5);
      if ($len) {
        $rsp = fread($fp, $len + 1);
        if ($rsp) {
          $key = substr($rsp, 95);
          \Drupal::logger('Key Connect')->notice('Primary server not found, successfully used backup server %server.', array('%server' => $bkupserver));
        }
      }
      fclose($fp);
    }
    else {
      $message = t('An error occurred');
      drupal_set_message($message, 'error', TRUE);
      \Drupal::logger('Key Connect')->notice('No Key Server Found', []);
    }
    return $key;
  }
}