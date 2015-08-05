<?php

namespace Drupal\townsec_key\Plugin\EncryptionMethod;

use Drupal\encrypt\EncryptionMethodInterface;
use Drupal\Core\Plugin\PluginBase;

/**
 * Class TownSecAES
 * @package Drupal\townsec_key\Plugin\EncryptionMethod
 *
 * Plugin definition for the Townsend Security AES encryption method.
 *
 * @EncryptionMethod(
 *   id = "townsec_aes",
 *   title = @Translation("Townsend Security AES"),
 *   description = "This encryption method uses the Townsend Security Alliance Key Manager onboard AES encryption to provide remote NIST certified encryption of sensitive data."
 * )
 */
class TownSecAES extends PluginBase implements EncryptionMethodInterface {

  /**
   * @return mixed
   */
  public function getDependencies() {
    return array();
  }

  /**
   * @return mixed
   */
  public function encrypt($text, $key, $options = array()) {
    $primencrypt = $key['primary_server']['akm_encrypt_port'];
    $bkupencrypt = $key['backup_server']['akm_encrypt_port'];
    $primserver = 'tls://' . $key['primary_server']['akm_host_server'] . ':' . $primencrypt;
    $bkupserver = 'tls://' . $key['backup_server']['akm_backup_server'] . ':' . $bkupencrypt;
    $keyname = $key['key_name'];
    $errno = NULL;
    $errstr = NULL;
    $primlocal = \Drupal::root() . '/' . $key['primary_server']['client_cert_and_key_file'];
    $primca = \Drupal::root() . '/' . $key['primary_server']['ca_cert_file'];
    $bkuplocal = \Drupal::root() . '/' . $key['backup_server']['client_cert_and_key_file'];
    $bkupca = \Drupal::root() . '/' . $key['backup_server']['ca_cert_file'];

    // Create TLS Connection with provided key locations.
    $primopts = array(
      'ssl' => array(
        'cafile' => $primca,
        'capture_peer_cert' => TRUE,
        'verify_peer_name' => FALSE,
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
    if ($fp = stream_socket_client($primserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $primctx)) {
      // Initiate the primary connection.
    }
    elseif ($fp = stream_socket_client($bkupserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $bkupctx)) {
      // Create backup connection.
    }
    if ($fp == FALSE) {
      return '';
    }

    // Generate a random IV to use w/ the encryption.
    $iv = user_password(16);
    // make text length an even multiple of 16
    $textlen = strlen($text);
    $totallen = $textlen + (16 - $textlen % 16);
    $text = sprintf("% -{$totallen}s", $text);
    $textcount = sprintf('%05d', $totallen);
    // Key Length = 40 (left justify pad on right).
    $key = sprintf('% -40s', $keyname);
    // Instance = 24 (leave blank for default instance).
    $inst = str_repeat(' ', 24);
    $request = "000982019YNBIN{$textcount}YNYY{$iv}{$key}{$inst}{$text}";
    fwrite($fp, $request);
    $len = fread($fp, 5);
    $value = '';
    if ($len) {
      //Be sure to read all the way to the end of the returned values
      $rsp = fread($fp, $len);
      if ($rsp) {
        $codedlen = substr($rsp, 10, 5);
        $inst = substr($rsp, 15, 24);
        $cipher = fread($fp, $codedlen);
        $value = $iv . $inst . bin2hex($cipher);
      }
    }
    fclose($fp);

    return $value;
  }

  /**
   * @return mixed
   */
  public function decrypt($text, $key, $options = array()) {
    $primencrypt = $key['primary_server']['akm_encrypt_port'];
    $bkupencrypt = $key['backup_server']['akm_encrypt_port'];
    $primserver = 'tls://' . $key['primary_server']['akm_host_server'] . ':' . $primencrypt;
    $bkupserver = 'tls://' . $key['backup_server']['akm_backup_server'] . ':' . $bkupencrypt;
    $keyname = $key['key_name'];
    $errno = NULL;
    $errstr = NULL;
    $primlocal = \Drupal::root() . '/' . $key['primary_server']['client_cert_and_key_file'];
    $primca = \Drupal::root() . '/' . $key['primary_server']['ca_cert_file'];
    $bkuplocal = \Drupal::root() . '/' . $key['backup_server']['client_cert_and_key_file'];
    $bkupca = \Drupal::root() . '/' . $key['backup_server']['ca_cert_file'];

    // Create TLS Connection with provided key locations.
    $primopts = array(
      'ssl' => array(
        'cafile' => $primca,
        'capture_peer_cert' => TRUE,
        'verify_peer_name' => FALSE,
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
    if ($fp = stream_socket_client($primserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $primctx)) {
      // Initiate the primary connection.
    }
    elseif ($fp = stream_socket_client($bkupserver, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $bkupctx)) {
      // Create backup connection.
    }
    if ($fp == FALSE) {
      return '';
    }
    // Key Length = 40 (left justify pad on right).
    // Instance = 24 (leave blank or instance got back).

    $iv = substr($text, 0, 16);
    $inst = substr($text, 16, 24);
    $cipher = substr($text, 40);
    $cipherlen = strlen($cipher);
    $textcount = sprintf('%05d', $cipherlen);
    $key = sprintf('% -40s', $keyname);
    $codedlen = sprintf('%05d', $cipherlen);

    $decrypt_header = "001012021YNB16{$codedlen}BINYNYY{$iv}{$key}{$inst}";
    $request = $decrypt_header . $cipher;
    fwrite($fp, $request);

    $plain = '';
    $len = fread($fp, 5);
    if ($len) {
      $rsp = fread($fp, $len);
      if ($rsp) {
        $plainlen = substr($rsp, 10, 5);
        $padded = fread($fp, $plainlen);
        $plain = rtrim($padded);
      }
    }
    fclose($fp);

    return $plain;
  }
}
